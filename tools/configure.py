# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Lint as: python3
"""Tools that implements vendor-specific CTAP2 commands to configure OpenSK."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import getpass
import datetime
import os
import sys
from unittest.mock import patch
import uuid

import colorama
from tqdm.auto import tqdm

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from fido2 import ctap
from fido2 import ctap2
from fido2 import hid

OPENSK_VID_PID = (0x18D1, 0x0239)
OPENSK_VENDOR_CONFIGURE = 0x40


def fatal(msg):
    tqdm.write(
        f"{colorama.Fore.RED + colorama.Style.BRIGHT}fatal:"
        f"{colorama.Style.RESET_ALL} {msg}"
    )
    sys.exit(1)


def error(msg):
    tqdm.write(f"{colorama.Fore.RED}error:{colorama.Style.RESET_ALL} {msg}")


def info(msg):
    tqdm.write(
        f"{colorama.Fore.GREEN + colorama.Style.BRIGHT}info:"
        f"{colorama.Style.RESET_ALL} {msg}"
    )


def get_opensk_devices(batch_mode):
    devices = []
    for dev in hid.CtapHidDevice.list_devices():
        if (dev.descriptor.vid, dev.descriptor.pid) == OPENSK_VID_PID:
            if dev.capabilities & hid.CAPABILITY.CBOR:
                if batch_mode:
                    devices.append(ctap2.Ctap2(dev))
                else:
                    return [ctap2.Ctap2(dev)]
    return devices


import base64
import hashlib
import json
import struct

from fido2 import cbor

COSE_ALG_MAP = {
    "es256": -7,
    "ed25519": -8,
    "es384": -35,
    "es512": -36,
    "mldsa44": -48,
    "mldsa65": -49,
    "mldsa87": -50,
    "ed448": -53,
}

# NIST ML-DSA OIDs (2.16.840.1.101.3.4.3.{17,18,19}) in DER
MLDSA_OIDS_DER = {
    bytes.fromhex("0609608648016503040311"): ("mldsa44", -48, 1312),
    bytes.fromhex("0609608648016503040312"): ("mldsa65", -49, 1952),
    bytes.fromhex("0609608648016503040313"): ("mldsa87", -50, 2592),
}


def parse_mldsa_pkcs8_or_raw(data):
    """Extracts (alg_name, cose_alg, 32_byte_seed) from an ML-DSA PKCS#8 PEM/DER or raw seed."""
    der = data
    if b"-----BEGIN" in data:
        lines = [
            line.strip()
            for line in data.splitlines()
            if line.strip() and not line.strip().startswith(b"-----")
        ]
        der = base64.b64decode(b"".join(lines))
    for oid_bytes, (alg_name, cose_alg, _pk_len) in MLDSA_OIDS_DER.items():
        idx = der.find(oid_bytes)
        if idx != -1:
            rest = der[idx + len(oid_bytes) :]
            # RFC 9881 PKCS#8 privateKey OCTET STRING contains either:
            # - [0] IMPLICIT OCTET STRING (0x80 0x20 <32-byte seed>)
            # - OCTET STRING (0x04 0x20 <32-byte seed>)
            # - SEQUENCE { OCTET STRING (0x04 0x20 <32-byte seed>), ... }
            for tag in (b"\x80\x20", b"\x04\x20"):
                t_idx = rest[:16].find(tag)
                if t_idx != -1 and len(rest) >= t_idx + 2 + 32:
                    return alg_name, cose_alg, rest[t_idx + 2 : t_idx + 2 + 32]
    return None


def extract_cose_public_key_from_cert(cert, cert_der, cose_alg):
    """Extracts canonical CBOR-encoded COSE_Key bytes from the X.509 certificate."""
    for oid_bytes, (_alg_name, oid_cose_alg, pk_len) in MLDSA_OIDS_DER.items():
        bit_string_tag = bytes(
            [0x03, 0x82, ((pk_len + 1) >> 8) & 0xFF, (pk_len + 1) & 0xFF, 0x00]
        )
        spki_pattern = oid_bytes + bit_string_tag
        idx = cert_der.find(spki_pattern)
        if idx != -1 and len(cert_der) >= idx + len(spki_pattern) + pk_len:
            pk_start = idx + len(spki_pattern)
            pk_bytes = cert_der[pk_start : pk_start + pk_len]
            return cbor.encode({1: 7, 3: oid_cose_alg, -1: pk_bytes})
    pub_key = cert.public_key()
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        nums = pub_key.public_numbers()
        if isinstance(pub_key.curve, ec.SECP256R1):
            return cbor.encode(
                {
                    1: 2,
                    3: -7,
                    -1: 1,
                    -2: nums.x.to_bytes(32, "big"),
                    -3: nums.y.to_bytes(32, "big"),
                }
            )
        if isinstance(pub_key.curve, ec.SECP384R1):
            return cbor.encode(
                {
                    1: 2,
                    3: -35,
                    -1: 2,
                    -2: nums.x.to_bytes(48, "big"),
                    -3: nums.y.to_bytes(48, "big"),
                }
            )
        if isinstance(pub_key.curve, ec.SECP521R1):
            return cbor.encode(
                {
                    1: 2,
                    3: -36,
                    -1: 3,
                    -2: nums.x.to_bytes(66, "big"),
                    -3: nums.y.to_bytes(66, "big"),
                }
            )
    raw_pub = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if len(raw_pub) == 32:
        return cbor.encode({1: 1, 3: -8, -1: 6, -2: raw_pub})
    if len(raw_pub) == 57:
        return cbor.encode({1: 1, 3: -53, -1: 7, -2: raw_pub})
    fatal("Unable to construct COSE_Key from certificate public key.")


def fido_mtc_leaf_hash(
    ca_id, serial, not_before, not_after, aaguid_bytes, fw_version, pub_key_hash, extensions=b""
):
    """Computes RFC 9162 §2.1.1 leaf hash SHA-256(0x00 || FidoMtcLogEntry)."""
    buf = bytearray()
    buf.extend(struct.pack(">H", len(ca_id)))
    buf.extend(ca_id)
    buf.extend(struct.pack(">QQQ", serial, not_before, not_after))
    buf.extend(aaguid_bytes)
    if fw_version is not None:
        buf.append(1)
        buf.extend(struct.pack(">Q", fw_version))
    else:
        buf.append(0)
    buf.extend(pub_key_hash)
    buf.extend(struct.pack(">H", len(extensions)))
    buf.extend(extensions)
    return hashlib.sha256(b"\x00" + bytes(buf)).digest()


def merkle_node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_power_of_two_less_than(n):
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def compute_subtree_hash(leaf_hashes):
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = largest_power_of_two_less_than(n)
    left = compute_subtree_hash(leaf_hashes[:k])
    right = compute_subtree_hash(leaf_hashes[k:])
    return merkle_node_hash(left, right)


def compute_inclusion_proof(m, leaf_hashes):
    n = len(leaf_hashes)
    if n <= 1:
        return []
    k = largest_power_of_two_less_than(n)
    if m < k:
        path = compute_inclusion_proof(m, leaf_hashes[:k])
        path.append(compute_subtree_hash(leaf_hashes[k:]))
        return path
    else:
        path = compute_inclusion_proof(m - k, leaf_hashes[k:])
        path.append(compute_subtree_hash(leaf_hashes[:k]))
        return path


def encode_mtc_proof_tls(start, end, inclusion_path, extensions=b"", signatures=b""):
    """Encodes MTCProof in TLS binary presentation format (draft-ietf-plants-merkle-tree-certs §4.2)."""
    proof_concat = b"".join(inclusion_path)
    out = bytearray()
    out.extend(struct.pack(">H", len(extensions)))
    out.extend(extensions)
    out.extend(start.to_bytes(8, "big")[2:8])  # uint48 start
    out.extend(end.to_bytes(8, "big")[2:8])    # uint48 end
    out.extend(struct.pack(">H", len(proof_concat)))
    out.extend(proof_concat)
    sig_len = len(signatures)
    out.extend(bytes([(sig_len >> 16) & 0xFF, (sig_len >> 8) & 0xFF, sig_len & 0xFF]))
    out.extend(signatures)
    return bytes(out)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT = b"FIDO-MTC-SUBTREE-CHECKPOINT-V1\x00\x00"


def encode_mtc_subtree_checkpoint(ca_id, log_number, start, end, root_hash):
    """Encodes the 85-byte FidoMtcSubtreeCheckpoint message signed by the Root CA."""
    out = bytearray(FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT)
    out.extend(struct.pack(">H", len(ca_id)))
    out.extend(ca_id)
    out.extend(struct.pack(">H", log_number))
    out.extend(start.to_bytes(8, "big")[2:8])
    out.extend(end.to_bytes(8, "big")[2:8])
    out.extend(root_hash)
    return bytes(out)


def sign_subtree_checkpoint_with_root_ca(
    ca_id, log_number, start, end, root_hash, root_key_path, root_cert_path, use_lms=True
):
    """Signs FidoMtcSubtreeCheckpoint with the LMS Intermediate CA (alg=-46) or Enterprise Root CA key."""
    checkpoint = encode_mtc_subtree_checkpoint(
        ca_id, log_number, start, end, root_hash
    )
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lms_int_state = os.path.join(
        repo_root, "crypto_data_lms", "intermediates", "lms_intermediate_0.state.json"
    )
    if use_lms and os.path.exists(lms_int_state):
        import gen_lms_certs

        lms_ca = gen_lms_certs.StatefulHssLmsCa.load(lms_int_state)
        q_slot = 4 if ca_id == bytes.fromhex("83993f0101") else 5
        _, sig = lms_ca.sign_hss(checkpoint, explicit_q=q_slot)
        return gen_lms_certs.COSE_ALG_HSS_LMS, sig

    if not (os.path.exists(root_key_path) and os.path.exists(root_cert_path)):
        return None
    import subprocess
    import tempfile

    with open(root_key_path, "rb") as rkf:
        parsed = parse_mldsa_pkcs8_or_raw(rkf.read())
    root_alg = parsed[1] if parsed else -50
    with (
        tempfile.NamedTemporaryFile() as mf,
        tempfile.NamedTemporaryFile() as sf,
    ):
        mf.write(checkpoint)
        mf.flush()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                root_key_path,
                "-rawin",
                "-in",
                mf.name,
                "-out",
                sf.name,
            ],
            check=True,
        )
        sig = sf.read()
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-certin",
                "-inkey",
                root_cert_path,
                "-rawin",
                "-in",
                mf.name,
                "-sigfile",
                sf.name,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return root_alg, sig


def get_private_key(data, password=None):
    # First we try without password.
    try:
        return serialization.load_pem_private_key(data, password=password)
    except TypeError:
        # Maybe we need a password then.
        if sys.stdin.isatty():
            password = getpass.getpass(prompt="Private key password: ")
        else:
            password = sys.stdin.readline().rstrip()
        return get_private_key(data, password=password.encode(sys.stdin.encoding))


def extract_key_material(raw_key_data):
    """Returns (cose_alg_or_none_for_legacy_p256, raw_key_bytes, priv_key_obj_or_none)."""
    mldsa_parsed = parse_mldsa_pkcs8_or_raw(raw_key_data)
    if mldsa_parsed is not None:
        alg_name, cose_alg, seed = mldsa_parsed
        info(f"Detected {alg_name.upper()} private key (32-byte seed).")
        return cose_alg, seed, None

    priv_key = get_private_key(raw_key_data)
    if isinstance(priv_key, ec.EllipticCurvePrivateKey):
        if isinstance(priv_key.curve, ec.SECP256R1):
            key_bytes = priv_key.private_numbers().private_value.to_bytes(
                length=32, byteorder="big", signed=False
            )
            return None, key_bytes, priv_key
        if isinstance(priv_key.curve, ec.SECP384R1):
            key_bytes = priv_key.private_numbers().private_value.to_bytes(
                length=48, byteorder="big", signed=False
            )
            return -35, key_bytes, priv_key
        if isinstance(priv_key.curve, ec.SECP521R1):
            key_bytes = priv_key.private_numbers().private_value.to_bytes(
                length=66, byteorder="big", signed=False
            )
            return -36, key_bytes, priv_key
        fatal(f"Unsupported elliptic curve: {priv_key.curve.name}")

    raw_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if len(raw_bytes) == 32:
        return -8, raw_bytes, priv_key
    if len(raw_bytes) == 57:
        return -53, raw_bytes, priv_key
    fatal("Unsupported private key type.")


def main(args):
    colorama.init()

    cose_alg, key_bytes, priv_key = extract_key_material(args.priv_key.read())
    info("Private key is valid.")

    cert_pem = args.certificate.read()
    cert = x509.load_pem_x509_certificate(cert_pem)
    # Some sanity/validity checks
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_before_utc > now:
        fatal("Certificate validity starts in the future.")
    if cert.not_valid_after_utc <= now:
        fatal("Certificate expired.")
    if priv_key is not None and isinstance(priv_key, ec.EllipticCurvePrivateKey):
        pub_key = cert.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            fatal("Certificate public key must be an Elliptic Curve one.")
        if pub_key.public_numbers() != priv_key.public_key().public_numbers():
            fatal("Certificate public doesn't match with the private key.")
    info("Certificate is valid.")

    aaguid_str = args.aaguid_file.read().strip()
    try:
        aaguid_obj = uuid.UUID(aaguid_str)
    except ValueError:
        fatal("Invalid AAGUID UUID format.")
    aaguid_bytes = aaguid_obj.bytes
    info(f"AAGUID to program: {aaguid_obj}")

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    MTC_NON_EXPIRING_NOT_AFTER = 253402300799  # 9999-12-31T23:59:59Z (RFC 5280 §4.1.2.5 / WebAuthn Level 4 §8.10)
    auto_mtc_default = "mtc"
    mtc_format = args.mtc_format or (auto_mtc_default if args.mtc else None)
    if mtc_format is not None:
        default_indices = {
            -48: 0,
            -49: 1,
            -50: 2,
        }
        ca_id_hex = args.mtc_ca_id or "83993f0101"
        ca_id = bytes.fromhex(ca_id_hex)
        batch_size = args.mtc_batch_size
        our_index = (
            args.mtc_index
            if args.mtc_index is not None
            else default_indices.get(cose_alg, 0)
        )
        if our_index < 0 or our_index >= batch_size:
            fatal(f"--mtc-index ({our_index}) must be in [0, {batch_size}).")
        not_before = int(cert.not_valid_before_utc.timestamp())
        not_after = (
            int(cert.not_valid_after_utc.timestamp())
            if args.mtc_use_cert_expiry
            else MTC_NON_EXPIRING_NOT_AFTER
        )
        fw_version = args.mtc_fw_version

        canonical_cose_pk = extract_cose_public_key_from_cert(cert, cert_der, cose_alg)
        pub_key_hash = hashlib.sha256(canonical_cose_pk).digest()
        our_serial = (args.mtc_log_number << 48) | our_index

        # Option A (Shared caId / Single MtcTrustAnchor):
        # Populate leaves 0 (-48), 1 (-49), 2 (-50) from sibling crypto_data_mldsa* certs
        # when present so all three batch keys authenticate against the exact same rootHash.
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sibling_cert_specs = [
            (0, -48, os.path.join(repo_root, "crypto_data_mldsa44", "fidont_cert.pem")),
            (1, -49, os.path.join(repo_root, "crypto_data_mldsa65", "fidont_cert.pem")),
            (2, -50, os.path.join(repo_root, "crypto_data_mldsa87", "fidont_cert.pem")),
        ]
        leaf_entries_by_index = {}
        batch_keys_entries = []
        if args.mtc_index is None and cose_alg in default_indices:
            for sib_idx, sib_alg, sib_cert_path in sibling_cert_specs:
                if sib_idx < batch_size and os.path.exists(sib_cert_path):
                    with open(sib_cert_path, "rb") as scf:
                        sib_cert = x509.load_pem_x509_certificate(scf.read())
                    sib_der = sib_cert.public_bytes(serialization.Encoding.DER)
                    sib_cose_pk = extract_cose_public_key_from_cert(sib_cert, sib_der, sib_alg)
                    sib_nb = int(sib_cert.not_valid_before_utc.timestamp())
                    sib_na = (
                        int(sib_cert.not_valid_after_utc.timestamp())
                        if args.mtc_use_cert_expiry
                        else MTC_NON_EXPIRING_NOT_AFTER
                    )
                    sib_serial = (args.mtc_log_number << 48) | sib_idx
                    leaf_entries_by_index[sib_idx] = (
                        sib_nb,
                        sib_na,
                        hashlib.sha256(sib_cose_pk).digest(),
                    )
                    batch_keys_entries.append(
                        {
                            "serial": sib_serial,
                            "alg": sib_alg,
                            "coseKey": b64url_encode(sib_cose_pk),
                        }
                    )

        leaf_entries_by_index[our_index] = (not_before, not_after, pub_key_hash)
        if not any(bk["serial"] == our_serial for bk in batch_keys_entries):
            batch_keys_entries.append(
                {
                    "serial": our_serial,
                    "alg": cose_alg if cose_alg is not None else -7,
                    "coseKey": b64url_encode(canonical_cose_pk),
                }
            )
            batch_keys_entries.sort(key=lambda x: x["serial"])

        leaf_hashes = []
        for idx in range(batch_size):
            serial = (args.mtc_log_number << 48) | idx
            if idx in leaf_entries_by_index:
                l_nb, l_na, pk_hash = leaf_entries_by_index[idx]
            else:
                l_nb, l_na, pk_hash = not_before, not_after, bytes([idx & 0xFF]) * 32
            leaf_hashes.append(
                fido_mtc_leaf_hash(
                    ca_id,
                    serial,
                    l_nb,
                    l_na,
                    aaguid_bytes,
                    fw_version,
                    pk_hash,
                )
            )
        landmark_root = compute_subtree_hash(leaf_hashes)
        inclusion_path = compute_inclusion_proof(our_index, leaf_hashes)
        mtc_proof_bytes = encode_mtc_proof_tls(0, batch_size, inclusion_path)

        mtc_cert_map = {
            "caId": ca_id,
            "serial": our_serial,
            "notBefore": not_before,
            "notAfter": not_after,
            "mtcProof": mtc_proof_bytes,
        }
        if fw_version is not None:
            mtc_cert_map["firmwareVersion"] = fw_version

        use_key_ref = not args.mtc_full_entry
        provisioned_mtc = {
            "fmt": mtc_format,
            "mtcCert": mtc_cert_map,
        }
        if use_key_ref:
            provisioned_mtc["keyRef"] = True
        if args.mtc_x5c:
            provisioned_mtc["x5c"] = cert_der

        # Second Non-Enterprise Batch Key + X.509 Certificate (`cKey` + `cX5c`)
        # for non-ML-DSA MakeCredential operations:
        if not args.no_classical_batch and cose_alg in (-48, -49, -50):
            default_classical_dir = os.path.join(repo_root, "crypto_data")
            c_key_raw = None
            if args.classical_priv_key is not None:
                c_key_raw = args.classical_priv_key.read()
            elif os.path.exists(os.path.join(default_classical_dir, "fidont.key")):
                with open(os.path.join(default_classical_dir, "fidont.key"), "rb") as ckf:
                    c_key_raw = ckf.read()

            c_cert_pem = None
            if args.classical_certificate is not None:
                c_cert_pem = args.classical_certificate.read()
            elif os.path.exists(os.path.join(default_classical_dir, "fidont_cert.pem")):
                with open(os.path.join(default_classical_dir, "fidont_cert.pem"), "rb") as ccf:
                    c_cert_pem = ccf.read()

            if c_key_raw is not None and c_cert_pem is not None:
                c_alg, c_key_bytes, _ = extract_key_material(c_key_raw)
                c_cert = x509.load_pem_x509_certificate(c_cert_pem)
                if c_cert.not_valid_before_utc > now:
                    fatal("Classical batch certificate validity starts in the future.")
                if c_cert.not_valid_after_utc <= now:
                    fatal("Classical batch certificate expired.")
                c_cert_der = c_cert.public_bytes(serialization.Encoding.DER)
                c_key_encoded = (
                    c_key_bytes
                    if c_alg is None
                    else cbor.encode([c_alg, c_key_bytes])
                )
                provisioned_mtc["cKey"] = c_key_encoded
                provisioned_mtc["cX5c"] = c_cert_der
                info(
                    f"Included second Non-Enterprise classical batch key "
                    f"(alg={c_alg if c_alg is not None else -7}, cKey={len(c_key_encoded)}B) "
                    f"and X.509 certificate (cX5c={len(c_cert_der)}B) for non-ML-DSA MakeCredential."
                )

        cert_or_mtc_bytes = cbor.encode(provisioned_mtc)
        info(
            f"Built MTC descriptor (default fmt='{mtc_format}', "
            f"supports 'mtc' and 'mtc-mds' via 0x0B): "
            f"{len(cert_or_mtc_bytes)} bytes (MTCProof={len(mtc_proof_bytes)}B, "
            f"path={len(inclusion_path)} hashes, serial=0x{our_serial:016x})"
        )

        if args.mtc_trust_anchor_out:
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            default_ent_dir = os.path.join(repo_root, "crypto_data_enterprise")
            root_key_path = os.path.join(default_ent_dir, "enterprise_root_ca.key")
            root_cert_path = os.path.join(default_ent_dir, "enterprise_root_ca.pem")
            subtree_entry = {
                "logNumber": args.mtc_log_number,
                "start": 0,
                "end": batch_size,
                "rootHash": b64url_encode(landmark_root),
            }
            signed = sign_subtree_checkpoint_with_root_ca(
                ca_id,
                args.mtc_log_number,
                0,
                batch_size,
                landmark_root,
                root_key_path,
                root_cert_path,
            )
            if signed is not None:
                root_alg, sig_bytes = signed
                subtree_entry["alg"] = root_alg
                subtree_entry["signature"] = b64url_encode(sig_bytes)
                info(
                    f"Signed Non-Enterprise MTC subtree checkpoint (caId='{b64url_encode(ca_id)}') "
                    f"with Enterprise Root CA (alg={root_alg}, sig={len(sig_bytes)}B)"
                )
            trust_anchor = {
                "caId": b64url_encode(ca_id),
                "hashAlg": "sha-256",
                "maxBatchWindow": not_after - not_before,
                "subtrees": [subtree_entry],
                "revokedSerials": [],
                "batchKeys": batch_keys_entries,
            }
            with open(args.mtc_trust_anchor_out, "w", encoding="utf-8") as f:
                json.dump(trust_anchor, f, indent=2)
            info(f"Wrote FIDO MDS MtcTrustAnchor JSON to {args.mtc_trust_anchor_out}")
    else:
        cert_or_mtc_bytes = cert_der

    MAX_INITIAL_CERT_CHUNK = 6000
    first_cert_chunk = cert_or_mtc_bytes[:MAX_INITIAL_CERT_CHUNK]
    extra_cert_chunk = cert_or_mtc_bytes[MAX_INITIAL_CERT_CHUNK:]

    cbor_data = {}
    cbor_data[1] = aaguid_bytes
    cbor_data[2] = {
        1: first_cert_chunk,
        2: key_bytes,
    }
    if cose_alg is not None:
        cbor_data[2][3] = cose_alg
    cbor_data[4] = 1  # AttestationId::Batch

    ent_cbor_data = None
    ent_extra_cert_chunk = b""
    if args.enterprise:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        default_ent_dir = os.path.join(repo_root, "crypto_data_enterprise")
        gen_ent_script = os.path.join(default_ent_dir, "gen_enterprise_key.py")
        if (
            args.enterprise_certificate is None
            and args.enterprise_priv_key is None
            and os.path.exists(gen_ent_script)
        ):
            import subprocess

            subprocess.run(
                [
                    sys.executable,
                    gen_ent_script,
                    "--serial",
                    args.enterprise_serial,
                    "--batch-size",
                    str(args.mtc_batch_size),
                    "--log-number",
                    str(args.mtc_log_number),
                    "--reuse-key",
                ],
                check=True,
            )

        if args.enterprise_priv_key is not None:
            ent_cose_alg, ent_key_bytes, ent_priv_key = extract_key_material(
                args.enterprise_priv_key.read()
            )
        elif os.path.exists(os.path.join(default_ent_dir, "fidont.key")):
            with open(os.path.join(default_ent_dir, "fidont.key"), "rb") as ekf:
                ent_cose_alg, ent_key_bytes, ent_priv_key = extract_key_material(
                    ekf.read()
                )
        else:
            ent_cose_alg, ent_key_bytes, ent_priv_key = cose_alg, key_bytes, priv_key

        if args.enterprise_certificate is not None:
            ent_cert_pem = args.enterprise_certificate.read()
            ent_cert = x509.load_pem_x509_certificate(ent_cert_pem)
            if ent_cert.not_valid_before_utc > now:
                fatal("Enterprise certificate validity starts in the future.")
            if ent_cert.not_valid_after_utc <= now:
                fatal("Enterprise certificate expired.")
            ent_cert_der = ent_cert.public_bytes(serialization.Encoding.DER)
        elif os.path.exists(os.path.join(default_ent_dir, "fidont_cert.pem")):
            with open(os.path.join(default_ent_dir, "fidont_cert.pem"), "rb") as ecf:
                ent_cert_pem = ecf.read()
            ent_cert = x509.load_pem_x509_certificate(ent_cert_pem)
            ent_cert_der = ent_cert.public_bytes(serialization.Encoding.DER)
        else:
            ent_cert = cert
            ent_cert_der = cert_der

        ent_ca_id_hex = args.enterprise_ca_id or "83993f0102"
        ent_ca_id = bytes.fromhex(ent_ca_id_hex)
        ent_batch_size = args.mtc_batch_size
        if args.enterprise_index is not None:
            ent_index = args.enterprise_index
        elif args.enterprise_serial.isdigit():
            ent_index = int(args.enterprise_serial) % ent_batch_size
        else:
            ent_index = 3
        if ent_index < 0 or ent_index >= ent_batch_size:
            fatal(f"--enterprise-index ({ent_index}) must be in [0, {ent_batch_size}).")
        ent_nb = int(ent_cert.not_valid_before_utc.timestamp())
        ent_na = (
            MTC_NON_EXPIRING_NOT_AFTER
            if args.enterprise_non_expiring
            else int(ent_cert.not_valid_after_utc.timestamp())
        )
        ent_fw_version = args.mtc_fw_version

        ent_cose_pk = extract_cose_public_key_from_cert(
            ent_cert, ent_cert_der, ent_cose_alg
        )
        ent_pk_hash = hashlib.sha256(ent_cose_pk).digest()
        ent_serial = (args.mtc_log_number << 48) | ent_index

        ent_serial_bytes = args.enterprise_serial.encode("utf-8")
        ent_leaf_hashes = []
        for idx in range(ent_batch_size):
            serial = (args.mtc_log_number << 48) | idx
            if idx == ent_index:
                l_nb, l_na, pk_h = ent_nb, ent_na, ent_pk_hash
                leaf_ext = ent_serial_bytes
            else:
                l_nb, l_na, pk_h = ent_nb, ent_na, bytes([(idx ^ 0xA5) & 0xFF]) * 32
                leaf_ext = b""
            ent_leaf_hashes.append(
                fido_mtc_leaf_hash(
                    ent_ca_id,
                    serial,
                    l_nb,
                    l_na,
                    aaguid_bytes,
                    ent_fw_version,
                    pk_h,
                    extensions=leaf_ext,
                )
            )
        ent_landmark_root = compute_subtree_hash(ent_leaf_hashes)
        ent_inclusion_path = compute_inclusion_proof(ent_index, ent_leaf_hashes)
        ent_mtc_proof_bytes = encode_mtc_proof_tls(
            0, ent_batch_size, ent_inclusion_path, extensions=ent_serial_bytes
        )

        ent_mtc_cert_map = {
            "caId": ent_ca_id,
            "serial": ent_serial,
            "notBefore": ent_nb,
            "notAfter": ent_na,
            "mtcProof": ent_mtc_proof_bytes,
        }
        if ent_fw_version is not None:
            ent_mtc_cert_map["firmwareVersion"] = ent_fw_version

        # Enterprise attestation always loads BOTH the single-device mtcCert descriptor
        # AND the per-enterprise-batch-key X.509 DER certificate (x5c) so that:
        # - "packed" first in 0x0B (or 0x0B empty/omitted when x5c fits in 7,609 B) returns fmt: "packed" with x5c
        # - "mtc" first in 0x0B (or 0x0B empty/omitted when x5c exceeds 7,609 B) returns fmt: "mtc" with inline pubKey + mtcCert
        ent_provisioned = {
            "fmt": "mtc",
            "x5c": ent_cert_der,
            "mtcCert": ent_mtc_cert_map,
        }
        if not args.mtc_full_entry:
            ent_provisioned["keyRef"] = True
        ent_cert_or_mtc_bytes = cbor.encode(ent_provisioned)
        info(
            f"Built Enterprise dual-format descriptor (fmt='mtc' + per-device x5c={len(ent_cert_der)}B, "
            f"FIDO serial='{args.enterprise_serial}'): "
            f"{len(ent_cert_or_mtc_bytes)} bytes total (MTCProof={len(ent_mtc_proof_bytes)}B, "
            f"mtcSerial=0x{ent_serial:016x})"
        )

        if args.enterprise_trust_anchor_out:
            subtree_entry = {
                "logNumber": args.mtc_log_number,
                "start": 0,
                "end": ent_batch_size,
                "rootHash": b64url_encode(ent_landmark_root),
            }
            default_ta_path = os.path.join(default_ent_dir, "mtc_trust_anchor.json")
            if os.path.exists(default_ta_path):
                with open(default_ta_path, "r", encoding="utf-8") as dtf:
                    gen_ta = json.load(dtf)
                gen_subtrees = gen_ta.get("subtrees", [])
                if (
                    gen_subtrees
                    and gen_subtrees[0].get("rootHash") == subtree_entry["rootHash"]
                    and "signature" in gen_subtrees[0]
                ):
                    subtree_entry["alg"] = gen_subtrees[0]["alg"]
                    subtree_entry["signature"] = gen_subtrees[0]["signature"]
            ent_trust_anchor = {
                "caId": b64url_encode(ent_ca_id),
                "hashAlg": "sha-256",
                "maxBatchWindow": ent_na - ent_nb,
                "subtrees": [subtree_entry],
                "revokedSerials": [],
                "batchKeys": [],
            }
            with open(args.enterprise_trust_anchor_out, "w", encoding="utf-8") as f:
                json.dump(ent_trust_anchor, f, indent=2)
            info(
                f"Wrote Enterprise FIDO MDS MtcTrustAnchor JSON to {args.enterprise_trust_anchor_out}"
            )

        ent_first_chunk = ent_cert_or_mtc_bytes[:MAX_INITIAL_CERT_CHUNK]
        ent_extra_cert_chunk = ent_cert_or_mtc_bytes[MAX_INITIAL_CERT_CHUNK:]
        ent_cbor_data = {
            2: {
                1: ent_first_chunk,
                2: ent_key_bytes,
            },
            4: 2,  # AttestationId::Enterprise
        }
        if ent_cose_alg is not None:
            ent_cbor_data[2][3] = ent_cose_alg

    patcher = None
    if args.use_vendor_hid:
        patcher = patch.object(hid.base, "FIDO_USAGE_PAGE", 0xFF00)
        patcher.start()
        info("Using the Vendor HID interface")

    devices = get_opensk_devices(args.batch)
    if patcher:
        patcher.stop()
    responses = []
    if not devices:
        fatal("No devices found.")
    for authenticator in tqdm(devices):
        # If the device supports it, wink to show which device
        # we're going to program.
        if authenticator.device.capabilities & hid.CAPABILITY.WINK:
            authenticator.device.wink()
        aaguid = uuid.UUID(bytes=authenticator.get_info().aaguid)
        info(f"Programming OpenSK device AAGUID {aaguid} ({authenticator.device}).")
        if args.priv_key:
            info("Please touch the device to confirm...")
        try:
            authenticator._max_msg_size = max(authenticator._max_msg_size, 65535)
            result = authenticator.send_cbor(
                OPENSK_VENDOR_CONFIGURE,
                data=cbor_data,
            )
            if extra_cert_chunk:
                result = authenticator.send_cbor(
                    OPENSK_VENDOR_CONFIGURE,
                    data={3: extra_cert_chunk, 4: 1},
                )
            if ent_cbor_data is not None:
                info("Programming Enterprise Attestation key + dual (mtcCert + x5c) certificate (touch if prompted)...")
                result = authenticator.send_cbor(
                    OPENSK_VENDOR_CONFIGURE,
                    data=ent_cbor_data,
                )
                if ent_extra_cert_chunk:
                    result = authenticator.send_cbor(
                        OPENSK_VENDOR_CONFIGURE,
                        data={3: ent_extra_cert_chunk, 4: 2},
                    )
            status = {"cert": result[1], "pkey": result[2], "aaguid": result[3]}
            responses.append(status)
            info(f"Certificate: {'Present' if result[1] else 'Missing'}")
            info(f"Private Key: {'Present' if result[2] else 'Missing'}")
            info(f"AAGUID:      {'Present' if result[3] else 'Missing'}")
        except ctap.CtapError as ex:
            if ex.code.value == ctap.CtapError.ERR.INVALID_COMMAND:
                error("Failed to configure OpenSK (unsupported command).")
            elif ex.code.value == 0xF2:  # VENDOR_INTERNAL_ERROR
                error(
                    (
                        "Failed to configure OpenSK (lockdown conditions not met "
                        "or hardware error)."
                    )
                )
            elif ex.code.value == ctap.CtapError.ERR.INVALID_PARAMETER:
                error(
                    (
                        "Failed to configure OpenSK (device is partially programmed but "
                        "the given cert/key don't match the ones currently programmed)."
                    )
                )
            else:
                error(f"Failed to configure OpenSK (unknown error: {ex})")
    return responses


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--batch",
        default=False,
        action="store_true",
        help=(
            "When batch processing is used, all plugged OpenSK devices will "
            "be programmed the same way. Otherwise (default) only the first seen "
            "device will be programmed."
        ),
    )
    parser.add_argument(
        "--certificate",
        type=argparse.FileType("rb"),
        required=True,
        metavar="PEM_FILE",
        dest="certificate",
        help=(
            "PEM file containing the certificate to inject into "
            "the OpenSK authenticator."
        ),
    )
    parser.add_argument(
        "--private-key",
        type=argparse.FileType("rb"),
        required=True,
        metavar="PEM_FILE",
        dest="priv_key",
        help=("PEM file containing the private key associated with the certificate."),
    )
    parser.add_argument(
        "--aaguid",
        type=argparse.FileType("r"),
        required=True,
        metavar="AAGUID_TXT_FILE",
        dest="aaguid_file",
        help="Path to aaguid.txt containing the UUID string.",
    )
    parser.add_argument(
        "--vendor-hid",
        default=False,
        action="store_true",
        dest="use_vendor_hid",
        help=("Whether to configure the device using the Vendor HID interface."),
    )
    parser.add_argument(
        "--mtc",
        default=False,
        action="store_true",
        dest="mtc",
        help=(
            "Program a Merkle Tree Certificate (MTC) descriptor instead of a raw X.509 DER "
            "certificate. The single provisioned batch key and inclusion proof will dynamically "
            "serve both 'mtc' and 'mtc-mds' attestations."
        ),
    )
    parser.add_argument(
        "--mtc-format",
        choices=["mtc", "mtc-keyref", "mtc-mds"],
        default=None,
        dest="mtc_format",
        help=(
            "Default MTC attestation format ('mtc', 'mtc-keyref', or 'mtc-mds') when the client does not "
            "specify CTAP 2.3 attestationFormatsPreference (0x0B)."
        ),
    )
    parser.add_argument(
        "--mtc-full-entry",
        default=False,
        action="store_true",
        dest="mtc_full_entry",
        help=(
            "Emit full mtcEntryDesc ({caId, serial, notBefore, notAfter, firmwareVersion, mtcProof}) "
            "for Batch MTC instead of the default compact proof-less mtcKeyRef ({caId, serial})."
        ),
    )
    parser.add_argument(
        "--mtc-use-cert-expiry",
        default=False,
        action="store_true",
        dest="mtc_use_cert_expiry",
        help=(
            "Use the X.509 certificate's notAfter timestamp for Batch MTC instead of the default "
            "non-expiring timestamp 253402300799 (9999-12-31T23:59:59Z)."
        ),
    )
    parser.add_argument(
        "--enterprise-non-expiring",
        default=False,
        action="store_true",
        dest="enterprise_non_expiring",
        help="Use non-expiring notAfter = 253402300799 (9999-12-31T23:59:59Z) for Enterprise MTC.",
    )
    parser.add_argument(
        "--mtc-x5c",
        default=False,
        action="store_true",
        dest="mtc_x5c",
        help="Also store the batch X.509 DER certificate (x5c) inside the MTC descriptor.",
    )
    parser.add_argument(
        "--classical-certificate",
        type=argparse.FileType("rb"),
        default=None,
        metavar="PEM_FILE",
        dest="classical_certificate",
        help=(
            "Optional PEM file for the second Non-Enterprise (classical) batch X.509 certificate "
            "used on non-ML-DSA MakeCredential operations (defaults to crypto_data/fidont_cert.pem)."
        ),
    )
    parser.add_argument(
        "--classical-private-key",
        type=argparse.FileType("rb"),
        default=None,
        metavar="PEM_FILE",
        dest="classical_priv_key",
        help=(
            "Optional PEM file for the second Non-Enterprise (classical) batch private key "
            "used on non-ML-DSA MakeCredential operations (defaults to crypto_data/fidont.key)."
        ),
    )
    parser.add_argument(
        "--no-classical-batch",
        default=False,
        action="store_true",
        dest="no_classical_batch",
        help="Disable provisioning the second Non-Enterprise classical batch key/certificate.",
    )
    parser.add_argument(
        "--mtc-ca-id",
        default=None,
        dest="mtc_ca_id",
        help="Hex-encoded IETF PLANTS TrustAnchorID (caId) for the MTC batch CA (default: 83993f0101 / 'g5k_AQE').",
    )
    parser.add_argument(
        "--mtc-log-number",
        type=int,
        default=7,
        dest="mtc_log_number",
        help="16-bit MTC batch issuance log number (default: 7).",
    )
    parser.add_argument(
        "--mtc-index",
        type=int,
        default=None,
        dest="mtc_index",
        help="Leaf index of this authenticator batch key in the MTC tree (defaults to 0 for -48, 1 for -49, 2 for -50).",
    )
    parser.add_argument(
        "--mtc-batch-size",
        type=int,
        default=8,
        dest="mtc_batch_size",
        help="Total number of leaves in the MTC batch tree (default: 8).",
    )
    parser.add_argument(
        "--mtc-fw-version",
        type=int,
        default=None,
        dest="mtc_fw_version",
        help="Optional firmware version integer committed in the FidoMtcLogEntry.",
    )
    parser.add_argument(
        "--mtc-trust-anchor-out",
        default=None,
        metavar="JSON_FILE",
        dest="mtc_trust_anchor_out",
        help="Optional path to write the FIDO MDS MtcTrustAnchor JSON for Relying Party verification.",
    )
    parser.add_argument(
        "--enterprise",
        default=False,
        action="store_true",
        dest="enterprise",
        help=(
            "Also provision the Enterprise single-device batch key (AttestationId::Enterprise = 2) "
            "with both an Enterprise MTC descriptor (mtcCert) and the per-enterprise-batch-key "
            "X.509 DER certificate (x5c)."
        ),
    )
    parser.add_argument(
        "--enterprise-serial",
        default="123456",
        dest="enterprise_serial",
        help=(
            'Settable FIDO Enterprise serial number (OID 1.3.6.1.4.1.45724.1.1.2) for the '
            'Enterprise key and X.509 certificate (default: "123456").'
        ),
    )
    parser.add_argument(
        "--enterprise-certificate",
        type=argparse.FileType("rb"),
        default=None,
        metavar="PEM_FILE",
        dest="enterprise_certificate",
        help="Optional PEM file for the per-device Enterprise X.509 certificate (defaults to crypto_data_enterprise/fidont_cert.pem).",
    )
    parser.add_argument(
        "--enterprise-private-key",
        type=argparse.FileType("rb"),
        default=None,
        metavar="PEM_FILE",
        dest="enterprise_priv_key",
        help="Optional PEM file for the per-device Enterprise private key (defaults to crypto_data_enterprise/fidont.key).",
    )
    parser.add_argument(
        "--enterprise-ca-id",
        default=None,
        dest="enterprise_ca_id",
        help="Hex-encoded IETF PLANTS TrustAnchorID (caId) for the Enterprise MTC CA (default: 83993f0102 / 'g5k_AQI').",
    )
    parser.add_argument(
        "--enterprise-index",
        type=int,
        default=None,
        dest="enterprise_index",
        help="Leaf index of this device's unique Enterprise key in the Enterprise MTC tree (defaults to int(--enterprise-serial) %% batch_size).",
    )
    parser.add_argument(
        "--enterprise-trust-anchor-out",
        default=None,
        metavar="JSON_FILE",
        dest="enterprise_trust_anchor_out",
        help="Optional path to write the Enterprise FIDO MDS MtcTrustAnchor JSON (with batchKeys=[]).",
    )
    main(parser.parse_args())

