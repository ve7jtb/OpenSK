#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
"""Generates Enterprise single-device batch key, X.509 certificate (with FIDO Serial Number
extension 1.3.6.1.4.1.45724.1.1.2), and MTC attestation info in crypto_data_enterprise/."""

import argparse
import base64
import datetime
import hashlib
import json
import os
import subprocess
import struct
import sys
import uuid

# NIST ML-DSA OIDs (2.16.840.1.101.3.4.3.{17,18,19}) in DER
MLDSA_SPECS = {
    "ML-DSA-44": (bytes.fromhex("0609608648016503040311"), -48, 1312),
    "ML-DSA-65": (bytes.fromhex("0609608648016503040312"), -49, 1952),
    "ML-DSA-87": (bytes.fromhex("0609608648016503040313"), -50, 2592),
}

FIDO_AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4"
FIDO_FWVERSION_OID = "1.3.6.1.4.1.45724.1.1.3"
FIDO_SERIAL_OID = "1.3.6.1.4.1.45724.1.1.2"


def read_opensk_firmware_version(repo_root: str) -> int:
    """Reads OPENSK_FIRMWARE_VERSION (or firmware_version() -> Some(N)) from src/env.rs."""
    import re

    env_rs_path = os.path.join(repo_root, "src", "env.rs")
    if os.path.exists(env_rs_path):
        with open(env_rs_path, "r", encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"OPENSK_FIRMWARE_VERSION\s*:\s*u64\s*=\s*(0x[0-9a-fA-F_]+|\d+)", text)
        if m:
            return int(m.group(1).replace("_", ""), 0)
        m2 = re.search(r"fn\s+firmware_version\s*\([^)]*\)\s*->\s*Option<u64>\s*\{\s*Some\((0x[0-9a-fA-F_]+|\d+)\)", text)
        if m2:
            return int(m2.group(1).replace("_", ""), 0)
    return 256


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def cbor_encode_uint(major: int, val: int) -> bytes:
    prefix = major << 5
    if val < 24:
        return bytes([prefix | val])
    if val <= 0xFF:
        return bytes([prefix | 24, val])
    if val <= 0xFFFF:
        return struct.pack(">BH", prefix | 25, val)
    if val <= 0xFFFFFFFF:
        return struct.pack(">BI", prefix | 26, val)
    return struct.pack(">BQ", prefix | 27, val)


def cbor_encode(obj) -> bytes:
    """Canonical CBOR encoder (RFC 8949 §4.2) for integers, bytes, strings, lists, and dicts."""
    if isinstance(obj, int):
        if obj >= 0:
            return cbor_encode_uint(0, obj)
        return cbor_encode_uint(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return cbor_encode_uint(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        utf8 = obj.encode("utf-8")
        return cbor_encode_uint(3, len(utf8)) + utf8
    if isinstance(obj, list):
        return cbor_encode_uint(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        encoded_items = [(cbor_encode(k), cbor_encode(v)) for k, v in obj.items()]
        encoded_items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return cbor_encode_uint(5, len(encoded_items)) + b"".join(
            k_b + v_b for k_b, v_b in encoded_items
        )
    raise TypeError(f"Unsupported CBOR type: {type(obj)}")


def extract_cose_public_key_from_der(cert_der: bytes) -> tuple[int, bytes]:
    """Extracts (cose_alg, canonical_cbor_cose_key) from an HSS-LMS, ML-DSA, or P-256 X.509 DER cert."""
    # Check HSS-LMS OID 1.2.840.113549.1.9.16.3.17 (30 0d 06 0b 2a 86 48 86 f7 0d 01 09 10 03 11 03 3d 00 <60B HSS pubkey>)
    hss_pattern = bytes.fromhex("300d060b2a864886f70d0109100311033d00")
    idx = cert_der.find(hss_pattern)
    if idx != -1 and len(cert_der) >= idx + len(hss_pattern) + 60:
        pk_start = idx + len(hss_pattern)
        pk_bytes = cert_der[pk_start : pk_start + 60]
        return -46, cbor_encode({1: 7, 3: -46, -1: pk_bytes})
    for _alg_name, (oid_bytes, cose_alg, pk_len) in MLDSA_SPECS.items():
        bit_string_tag = bytes(
            [0x03, 0x82, ((pk_len + 1) >> 8) & 0xFF, (pk_len + 1) & 0xFF, 0x00]
        )
        spki_pattern = oid_bytes + bit_string_tag
        idx = cert_der.find(spki_pattern)
        if idx != -1 and len(cert_der) >= idx + len(spki_pattern) + pk_len:
            pk_start = idx + len(spki_pattern)
            pk_bytes = cert_der[pk_start : pk_start + pk_len]
            return cose_alg, cbor_encode({1: 7, 3: cose_alg, -1: pk_bytes})
    # Check P-256 uncompressed point (0x03 0x42 0x00 0x04 <32B X> <32B Y>)
    p256_tag = b"\x03\x42\x00\x04"
    idx = cert_der.find(p256_tag)
    if idx != -1 and len(cert_der) >= idx + 4 + 64:
        x_bytes = cert_der[idx + 4 : idx + 4 + 32]
        y_bytes = cert_der[idx + 4 + 32 : idx + 4 + 64]
        return -7, cbor_encode({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})
    raise ValueError("Unable to extract public key from certificate DER.")


def parse_cert_timestamps(cert_pem_path: str) -> tuple[int, int]:
    """Extracts (not_before_unix, not_after_unix) using openssl x509 -dates."""
    out = subprocess.check_output(
        ["openssl", "x509", "-in", cert_pem_path, "-noout", "-dates"],
        text=True,
    )
    not_before = None
    not_after = None
    for line in out.splitlines():
        if line.startswith("notBefore="):
            dt_str = line.split("=", 1)[1].strip()
            dt = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
            not_before = int(dt.timestamp())
        elif line.startswith("notAfter="):
            dt_str = line.split("=", 1)[1].strip()
            dt = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
            not_after = int(dt.timestamp())
    if not_before is None or not_after is None:
        raise RuntimeError("Failed to parse certificate validity dates.")
    return not_before, not_after


def fido_mtc_leaf_hash(
    ca_id: bytes,
    serial: int,
    not_before: int,
    not_after: int,
    aaguid_bytes: bytes,
    fw_version: int | None,
    pub_key_hash: bytes,
    extensions: bytes = b"",
) -> bytes:
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


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def compute_subtree_hash(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = largest_power_of_two_less_than(n)
    left = compute_subtree_hash(leaf_hashes[:k])
    right = compute_subtree_hash(leaf_hashes[k:])
    return merkle_node_hash(left, right)


def compute_inclusion_proof(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    n = len(leaf_hashes)
    if n <= 1:
        return []
    k = largest_power_of_two_less_than(n)
    if m < k:
        path = compute_inclusion_proof(m, leaf_hashes[:k])
        path.append(compute_subtree_hash(leaf_hashes[k:]))
        return path
    path = compute_inclusion_proof(m - k, leaf_hashes[k:])
    path.append(compute_subtree_hash(leaf_hashes[:k]))
    return path


FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT = b"FIDO-MTC-SUBTREE-CHECKPOINT-V1\x00\x00"


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def encode_mtc_subtree_checkpoint(
    ca_id: bytes,
    log_number: int,
    start: int,
    end: int,
    root_hash: bytes,
) -> bytes:
    """Encodes the 85-byte FidoMtcSubtreeCheckpoint message signed by the Root CA:
    context[32] || uint16(len(caId)) || caId || uint16(logNumber) || uint48(start) || uint48(end) || rootHash[32]."""
    out = bytearray(FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT)
    out.extend(struct.pack(">H", len(ca_id)))
    out.extend(ca_id)
    out.extend(struct.pack(">H", log_number))
    out.extend(start.to_bytes(8, "big")[2:8])
    out.extend(end.to_bytes(8, "big")[2:8])
    out.extend(root_hash)
    return bytes(out)


def sign_and_verify_subtree_checkpoint(
    root_key_path: str,
    root_cert_path: str,
    checkpoint_bytes: bytes,
) -> bytes:
    """Signs FidoMtcSubtreeCheckpoint with root_key_path and verifies against root_cert_path."""
    import tempfile

    with (
        tempfile.NamedTemporaryFile() as mf,
        tempfile.NamedTemporaryFile() as sf,
    ):
        mf.write(checkpoint_bytes)
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
        return sig


def verify_metadata_enterprise_ca_id(
    metadata_path: str, target_ca_id: str | None = None
) -> None:
    """Verifies that mtcTrustAnchors (both Non-Enterprise 'g5k_AQE' and Enterprise 'g5k_AQI',
    or a specific target_ca_id) are cryptographically signed by a Root CA certificate in
    attestationRootCertificates."""
    import tempfile

    with open(metadata_path, "r", encoding="utf-8") as f:
        mds = json.load(f)

    anchors = [
        ta
        for ta in mds.get("mtcTrustAnchors", [])
        if target_ca_id is None or ta.get("caId") == target_ca_id
    ]
    if not anchors:
        raise RuntimeError(f"No matching mtcTrustAnchors found in {metadata_path}")

    root_certs_b64 = mds.get("attestationRootCertificates", [])

    for ta in anchors:
        ca_id_str = ta["caId"]
        ca_id_bytes = b64url_decode(ca_id_str)
        for subtree in ta.get("subtrees", []):
            sig_b64 = subtree.get("signature")
            if not sig_b64:
                raise RuntimeError(
                    f"Subtree logNumber={subtree.get('logNumber')} in caId='{ca_id_str}' has no signature."
                )
            sig_bytes = b64url_decode(sig_b64)
            root_hash_bytes = b64url_decode(subtree["rootHash"])
            checkpoint = encode_mtc_subtree_checkpoint(
                ca_id_bytes,
                int(subtree["logNumber"]),
                int(subtree["start"]),
                int(subtree["end"]),
                root_hash_bytes,
            )
            verified_by_idx = None
            verified_subject = None
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            tools_dir = os.path.join(repo_root, "tools")
            if tools_dir not in os.sys.path:
                os.sys.path.insert(0, tools_dir)
            import gen_lms_certs

            for idx, cert_b64 in enumerate(root_certs_b64):
                cert_der = base64.b64decode(cert_b64)
                hss_pub = gen_lms_certs.extract_hss_pubkey_from_cert_der(cert_der)
                if hss_pub is not None and subtree.get("alg") == -46:
                    if gen_lms_certs.verify_hss_lms_signature(hss_pub, checkpoint, sig_bytes):
                        verified_by_idx = idx
                        verified_subject = f"HSS-LMS CA cert[{idx}] ({len(cert_der)} B DER)"
                        break
                pem_lines = [
                    "-----BEGIN CERTIFICATE-----",
                    *[cert_b64[i : i + 64] for i in range(0, len(cert_b64), 64)],
                    "-----END CERTIFICATE-----",
                    "",
                ]
                with (
                    tempfile.NamedTemporaryFile("w", suffix=".pem") as cf,
                    tempfile.NamedTemporaryFile() as mf,
                    tempfile.NamedTemporaryFile() as sf,
                ):
                    cf.write("\n".join(pem_lines))
                    cf.flush()
                    mf.write(checkpoint)
                    mf.flush()
                    sf.write(sig_bytes)
                    sf.flush()
                    res = subprocess.run(
                        [
                            "openssl",
                            "pkeyutl",
                            "-verify",
                            "-certin",
                            "-inkey",
                            cf.name,
                            "-rawin",
                            "-in",
                            mf.name,
                            "-sigfile",
                            sf.name,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if res.returncode == 0:
                        verified_by_idx = idx
                        verified_subject = subprocess.check_output(
                            ["openssl", "x509", "-in", cf.name, "-noout", "-subject"],
                            text=True,
                        ).strip()
                        break
            if verified_by_idx is None:
                raise RuntimeError(
                    f"Subtree signature for caId='{ca_id_str}' failed verification against all attestationRootCertificates!"
                )
            print(
                f"[VERIFIED] caId='{ca_id_str}' (0x{ca_id_bytes.hex()}) subtree "
                f"(logNumber={subtree['logNumber']}, start={subtree['start']}, end={subtree['end']}, "
                f"rootHash={subtree['rootHash']}) signature ({len(sig_bytes)} B, alg={subtree.get('alg')}) "
                f"is valid under attestationRootCertificates[{verified_by_idx}] ({verified_subject})"
            )


def encode_mtc_proof_tls(
    start: int,
    end: int,
    inclusion_path: list[bytes],
    extensions: bytes = b"",
    signatures: bytes = b"",
) -> bytes:
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


def write_fidont_ext_cnf(cnf_path: str, aaguid_hex: str, serial_str: str, fw_version: int = 256) -> None:
    content = f"""# Default FIDO Enterprise Serial Number (settable via gen_enterprise_key.py --serial)
FIDO_SERIAL_NUMBER = {serial_str}

[ req ]
distinguished_name = req_distinguished_name
x509_extensions     = fido_extensions
prompt              = no

[ req_distinguished_name ]
CN = Fidont Enterprise Attestation
O  = John Bradley
OU = Authenticator Attestation
C  = CA

[ fido_extensions ]
# Standard required extensions for a FIDO attestation certificate
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature

# FIDO2 AAGUID Custom Extension
# OID: {FIDO_AAGUID_OID} (id-fido-gen-ce-aaguid)
{FIDO_AAGUID_OID} = ASN1:FORMAT:HEX,OCT:{aaguid_hex.upper()}

# FIDO Authenticator Firmware Version Extension (non-critical OCTET STRING)
# OID: {FIDO_FWVERSION_OID} (id-fido-gen-ce-fwversion)
{FIDO_FWVERSION_OID} = ASN1:FORMAT:HEX,OCT:{fw_version:08X}

# FIDO Enterprise Attestation Serial Number Extension (non-critical OCTET STRING)
# OID: {FIDO_SERIAL_OID} (id-fido-gen-ce-sernum)
{FIDO_SERIAL_OID} = ASN1:OCTETSTRING:${{FIDO_SERIAL_NUMBER}}

[ root_ca_req ]
distinguished_name = root_ca_dn
x509_extensions     = root_ca_extensions
prompt              = no

[ root_ca_dn ]
CN = Fidont Enterprise Root CA
O  = John Bradley
OU = Authenticator Attestation
C  = CA

[ root_ca_extensions ]
basicConstraints     = critical, CA:TRUE, pathlen:0
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""
    with open(cnf_path, "w", encoding="utf-8") as f:
        f.write(content)


def write_batch_ext_cnf(cnf_path: str, aaguid_hex: str, fw_version: int = 256) -> None:
    content = f"""[ req ]
distinguished_name = req_distinguished_name
x509_extensions     = fido_extensions
prompt              = no

[ req_distinguished_name ]
CN = Fidont Attestation
O  = John Bradley
OU = Authenticator Attestation
C  = CA

[ fido_extensions ]
# Standard required extensions for a FIDO batch certificate
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature

# FIDO2 AAGUID Custom Extension
# OID: {FIDO_AAGUID_OID} (id-fido-gen-ce-aaguid)
{FIDO_AAGUID_OID} = ASN1:FORMAT:HEX,OCT:{aaguid_hex.upper()}

# FIDO Authenticator Firmware Version Extension (non-critical OCTET STRING)
# OID: {FIDO_FWVERSION_OID} (id-fido-gen-ce-fwversion)
{FIDO_FWVERSION_OID} = ASN1:FORMAT:HEX,OCT:{fw_version:08X}
"""
    with open(cnf_path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate ML-DSA-87 Enterprise Root CA, Enterprise batch key, X.509 certificate "
            "signed by the ML-DSA-87 Root CA with FIDO Serial Number extension "
            "(1.3.6.1.4.1.45724.1.1.2), and MTC info with Root-CA-signed subtree checkpoint."
        )
    )
    parser.add_argument(
        "--serial",
        default="123456",
        help='Settable FIDO Enterprise serial number for the key/certificate (default: "123456").',
    )
    parser.add_argument(
        "--alg",
        default="ML-DSA-44",
        choices=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "P-256"],
        help="Key algorithm for the Enterprise attestation key (default: ML-DSA-44).",
    )
    parser.add_argument(
        "--root-alg",
        default="ML-DSA-87",
        choices=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        help="Key algorithm for the Enterprise Root CA (default: ML-DSA-87).",
    )
    parser.add_argument(
        "--ca-id",
        default="83993f0102",
        help="Hex-encoded IETF PLANTS TrustAnchorID (caId) for Enterprise MTC CA (default: 83993f0102 / 'g5k_AQI').",
    )
    parser.add_argument(
        "--log-number",
        type=int,
        default=7,
        help="16-bit MTC batch issuance log number (default: 7).",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=None,
        help="Leaf index in the MTC subtree (defaults to int(serial) %% batch_size if numeric, else 3).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Number of leaves in the generated Enterprise MTC subtree (default: 8).",
    )
    parser.add_argument(
        "--fw-version",
        type=int,
        default=None,
        help="Firmware version integer committed in the FidoMtcLogEntry and X.509 cert (default: read from src/env.rs).",
    )
    parser.add_argument(
        "--ca-type",
        default="lms",
        choices=["lms", "mldsa"],
        help="CA hierarchy type used to sign PQ batch/enterprise certs and MTC checkpoints (default: lms).",
    )
    parser.add_argument(
        "--reuse-key",
        action="store_true",
        default=False,
        help="Reuse existing enterprise_root_ca.key/pem and fidont.key/fidont_cert.pem if present.",
    )
    parser.add_argument(
        "--verify-metadata",
        default=None,
        metavar="METADATA_JSON",
        help="Verify that caId 'g5k_AQI' in the given MDS3 metadata JSON is signed by the Enterprise CA in attestationRootCertificates.",
    )
    args = parser.parse_args()

    if args.verify_metadata:
        verify_metadata_enterprise_ca_id(args.verify_metadata)
        return

    ent_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(ent_dir)
    if args.fw_version is None:
        args.fw_version = read_opensk_firmware_version(repo_root)
    aaguid_path = os.path.join(ent_dir, "aaguid.txt")
    cnf_path = os.path.join(ent_dir, "fidont_ext.cnf")
    root_key_path = os.path.join(ent_dir, "enterprise_root_ca.key")
    root_cert_path = os.path.join(ent_dir, "enterprise_root_ca.pem")
    key_path = os.path.join(ent_dir, "fidont.key")
    csr_path = os.path.join(ent_dir, "fidont.csr")
    cert_path = os.path.join(ent_dir, "fidont_cert.pem")
    ecparams_path = os.path.join(ent_dir, "ecparams.pem")

    with open(aaguid_path, "r", encoding="utf-8") as f:
        aaguid_obj = uuid.UUID(f.read().strip())
    aaguid_bytes = aaguid_obj.bytes
    aaguid_hex = aaguid_bytes.hex().upper()

    # 1. Write fidont_ext.cnf with the requested serial number and firmware version
    write_fidont_ext_cnf(cnf_path, aaguid_hex, args.serial, args.fw_version)
    for b_dir_name in ["crypto_data", "crypto_data_mldsa44", "crypto_data_mldsa65", "crypto_data_mldsa87"]:
        b_dir = os.path.join(repo_root, b_dir_name)
        if os.path.isdir(b_dir):
            write_batch_ext_cnf(os.path.join(b_dir, "fidont_ext.cnf"), aaguid_hex, args.fw_version)

    serial_bytes = args.serial.encode("utf-8")
    fido_serial_ext_der = bytes([0x04, len(serial_bytes)]) + serial_bytes
    fw_version_bytes = struct.pack(">I", args.fw_version)
    fido_fwversion_ext_der = b"\x04\x04" + fw_version_bytes
    fido_fwversion_oid_der = bytes.fromhex("060b2b0601040182e51c010103")

    if args.ca_type == "lms":
        tools_dir = os.path.join(repo_root, "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        import gen_lms_certs as lms_mod

        lms_int_pem = os.path.join(repo_root, "crypto_data_lms", "intermediates", "lms_intermediate_0.pem")
        lms_int_state = os.path.join(repo_root, "crypto_data_lms", "intermediates", "lms_intermediate_0.state.json")

        # Ensure enterprise key exists before generating LMS batch certs
        if not (args.reuse_key and os.path.exists(key_path)):
            csr_cmd = ["openssl", "req", "-new", "-nodes", "-config", cnf_path]
            if args.alg == "P-256":
                csr_cmd.extend(["-newkey", f"ec:{ecparams_path}", "-keyout", key_path])
            else:
                csr_cmd.extend(["-newkey", args.alg, "-keyout", key_path])
            csr_cmd.extend(["-out", csr_path])
            subprocess.run(csr_cmd, check=True)

        if not (os.path.exists(lms_int_pem) and os.path.exists(lms_int_state)):
            lms_mod.generate_lms_hierarchy_and_batch_certs(
                repo_root, enterprise_serial=args.serial, fw_version=args.fw_version
            )

        root_cert_path = lms_int_pem
        root_key_path = lms_int_state
        int_ca = lms_mod.StatefulHssLmsCa.load(lms_int_state)
        int_hss_pub = int_ca.hss_public_key_bytes()

        reuse_existing_leaf_cert = False
        if args.reuse_key and os.path.exists(cert_path):
            existing_der = subprocess.check_output(
                ["openssl", "x509", "-in", cert_path, "-outform", "DER"]
            )
            if (
                fido_serial_ext_der in existing_der
                and fido_fwversion_oid_der in existing_der
                and fido_fwversion_ext_der in existing_der
                and lms_mod.verify_lms_x509_cert_der(existing_der, int_hss_pub)
            ):
                reuse_existing_leaf_cert = True

        if not reuse_existing_leaf_cert:
            lms_mod.generate_lms_hierarchy_and_batch_certs(
                repo_root, enterprise_serial=args.serial, fw_version=args.fw_version
            )
            int_ca = lms_mod.StatefulHssLmsCa.load(lms_int_state)
            int_hss_pub = int_ca.hss_public_key_bytes()
    else:
        # 2a. Generate (or reuse) the ML-DSA-87 Enterprise Root CA key & self-signed certificate
        if not (args.reuse_key and os.path.exists(root_key_path) and os.path.exists(root_cert_path)):
            root_cmd = [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-days",
                "3650",
                "-config",
                cnf_path,
                "-reqexts",
                "root_ca_extensions",
                "-extensions",
                "root_ca_extensions",
                "-subj",
                "/CN=Fidont Enterprise Root CA/O=John Bradley/OU=Authenticator Attestation/C=CA",
            ]
            if args.reuse_key and os.path.exists(root_key_path):
                root_cmd.extend(["-key", root_key_path])
            else:
                root_cmd.extend(["-newkey", args.root_alg, "-keyout", root_key_path])
            root_cmd.extend(["-out", root_cert_path])
            subprocess.run(root_cmd, check=True)

        # 2b. Check if existing fidont_cert.pem already has the requested FIDO serial and verifies under Root CA
        reuse_existing_leaf_cert = False
        if args.reuse_key and os.path.exists(key_path) and os.path.exists(cert_path):
            existing_der = subprocess.check_output(
                ["openssl", "x509", "-in", cert_path, "-outform", "DER"]
            )
            verify_res = subprocess.run(
                ["openssl", "verify", "-CAfile", root_cert_path, cert_path],
                capture_output=True,
            )
            if verify_res.returncode == 0 and fido_serial_ext_der in existing_der:
                reuse_existing_leaf_cert = True

        if not reuse_existing_leaf_cert:
            csr_cmd = ["openssl", "req", "-new", "-nodes", "-config", cnf_path]
            if args.reuse_key and os.path.exists(key_path):
                csr_cmd.extend(["-key", key_path])
            else:
                if args.alg == "P-256":
                    csr_cmd.extend(["-newkey", f"ec:{ecparams_path}", "-keyout", key_path])
                else:
                    csr_cmd.extend(["-newkey", args.alg, "-keyout", key_path])
            csr_cmd.extend(["-out", csr_path])
            subprocess.run(csr_cmd, check=True)

            sign_cmd = [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr_path,
                "-CA",
                root_cert_path,
                "-CAkey",
                root_key_path,
                "-CAcreateserial",
                "-days",
                "3650",
                "-extfile",
                cnf_path,
                "-extensions",
                "fido_extensions",
                "-out",
                cert_path,
            ]
            subprocess.run(sign_cmd, check=True)

        # 2c. Ensure all 3 non-enterprise ML-DSA batch X.509 certificates (mldsa44, mldsa65, mldsa87)
        # are also signed by the ML-DSA-87 Root CA (enterprise_root_ca.pem)
        for batch_dir_name in ["crypto_data_mldsa44", "crypto_data_mldsa65", "crypto_data_mldsa87"]:
            b_dir = os.path.join(repo_root, batch_dir_name)
            b_key = os.path.join(b_dir, "fidont.key")
            b_cnf = os.path.join(b_dir, "fidont_ext.cnf")
            b_csr = os.path.join(b_dir, "fidont.csr")
            b_cert = os.path.join(b_dir, "fidont_cert.pem")
            if not (os.path.exists(b_key) and os.path.exists(b_cnf)):
                continue
            needs_signing = True
            if args.reuse_key and os.path.exists(b_cert):
                iss_sub = subprocess.check_output(
                    ["openssl", "x509", "-in", b_cert, "-noout", "-issuer", "-subject"],
                    text=True,
                ).splitlines()
                v_res = subprocess.run(
                    ["openssl", "verify", "-CAfile", root_cert_path, b_cert],
                    capture_output=True,
                )
                if (
                    v_res.returncode == 0
                    and len(iss_sub) == 2
                    and iss_sub[0].split("=", 1)[1] != iss_sub[1].split("=", 1)[1]
                ):
                    needs_signing = False
            if needs_signing:
                subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-nodes",
                        "-key",
                        b_key,
                        "-config",
                        b_cnf,
                        "-out",
                        b_csr,
                    ],
                    check=True,
                )
                subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-in",
                        b_csr,
                        "-CA",
                        root_cert_path,
                        "-CAkey",
                        root_key_path,
                        "-CAcreateserial",
                        "-days",
                        "3650",
                        "-extfile",
                        b_cnf,
                        "-extensions",
                        "fido_extensions",
                        "-out",
                        b_cert,
                    ],
                    check=True,
                )

    # 2d. Generate (or reuse) alternate non-PQ ES384 Enterprise Root CA and sign the ES256 batch key (crypto_data/fidont_cert.pem)
    es384_root_key_path = os.path.join(ent_dir, "enterprise_root_ca_es384.key")
    es384_root_cert_path = os.path.join(ent_dir, "enterprise_root_ca_es384.pem")
    if not (
        args.reuse_key
        and os.path.exists(es384_root_key_path)
        and os.path.exists(es384_root_cert_path)
    ):
        if not (args.reuse_key and os.path.exists(es384_root_key_path)):
            subprocess.run(
                [
                    "openssl",
                    "ecparam",
                    "-name",
                    "secp384r1",
                    "-genkey",
                    "-noout",
                    "-out",
                    es384_root_key_path,
                ],
                check=True,
            )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                es384_root_key_path,
                "-sha384",
                "-days",
                "3650",
                "-config",
                cnf_path,
                "-reqexts",
                "root_ca_extensions",
                "-extensions",
                "root_ca_extensions",
                "-subj",
                "/CN=Fidont Enterprise Root CA ES384/O=John Bradley/OU=Authenticator Attestation/C=CA",
                "-out",
                es384_root_cert_path,
            ],
            check=True,
        )

    es256_dir = os.path.join(repo_root, "crypto_data")
    es256_key = os.path.join(es256_dir, "fidont.key")
    es256_cnf = os.path.join(es256_dir, "fidont_ext.cnf")
    es256_csr = os.path.join(es256_dir, "fidont.csr")
    es256_cert = os.path.join(es256_dir, "fidont_cert.pem")
    if os.path.exists(es256_key) and os.path.exists(es256_cnf):
        es256_needs_signing = True
        if args.reuse_key and os.path.exists(es256_cert):
            es256_der = subprocess.check_output(
                ["openssl", "x509", "-in", es256_cert, "-outform", "DER"]
            )
            iss_sub = subprocess.check_output(
                ["openssl", "x509", "-in", es256_cert, "-noout", "-issuer", "-subject"],
                text=True,
            ).splitlines()
            v_res = subprocess.run(
                ["openssl", "verify", "-CAfile", es384_root_cert_path, es256_cert],
                capture_output=True,
            )
            if (
                v_res.returncode == 0
                and len(iss_sub) == 2
                and iss_sub[0].split("=", 1)[1] != iss_sub[1].split("=", 1)[1]
                and fido_fwversion_oid_der in es256_der
                and fido_fwversion_ext_der in es256_der
            ):
                es256_needs_signing = False
        if es256_needs_signing:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-nodes",
                    "-key",
                    es256_key,
                    "-config",
                    es256_cnf,
                    "-out",
                    es256_csr,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    es256_csr,
                    "-CA",
                    es384_root_cert_path,
                    "-CAkey",
                    es384_root_key_path,
                    "-CAcreateserial",
                    "-sha384",
                    "-days",
                    "3650",
                    "-extfile",
                    es256_cnf,
                    "-extensions",
                    "fido_extensions",
                    "-out",
                    es256_cert,
                ],
                check=True,
            )

    # 3. Read DER certificate and extract COSE_Key and timestamps
    root_cert_der = subprocess.check_output(
        ["openssl", "x509", "-in", root_cert_path, "-outform", "DER"]
    )
    es384_root_cert_der = subprocess.check_output(
        ["openssl", "x509", "-in", es384_root_cert_path, "-outform", "DER"]
    )
    root_cose_alg, root_cose_pk = extract_cose_public_key_from_der(root_cert_der)
    cert_der = subprocess.check_output(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER"]
    )
    cose_alg, canonical_cose_pk = extract_cose_public_key_from_der(cert_der)
    pub_key_hash = hashlib.sha256(canonical_cose_pk).digest()
    not_before, _cert_not_after = parse_cert_timestamps(cert_path)
    # RFC 5280 §4.1.2.5 non-expiring GeneralizedTime 99991231235959Z (9999-12-31T23:59:59Z)
    not_after = 253402300799

    # 4. Compute Enterprise MTC serial and Merkle inclusion proof
    ca_id = bytes.fromhex(args.ca_id)
    batch_size = args.batch_size
    if args.index is not None:
        leaf_index = args.index
    elif args.serial.isdigit():
        leaf_index = int(args.serial) % batch_size
    else:
        leaf_index = int.from_bytes(hashlib.sha256(args.serial.encode("utf-8")).digest()[:4], "big") % batch_size

    mtc_serial = (args.log_number << 48) | leaf_index

    leaf_hashes = []
    for idx in range(batch_size):
        s_val = (args.log_number << 48) | idx
        if idx == leaf_index:
            pk_h = pub_key_hash
            leaf_ext = serial_bytes
        else:
            pk_h = bytes([(idx ^ 0xA5) & 0xFF]) * 32
            leaf_ext = b""
        leaf_hashes.append(
            fido_mtc_leaf_hash(
                ca_id,
                s_val,
                not_before,
                not_after,
                aaguid_bytes,
                args.fw_version,
                pk_h,
                extensions=leaf_ext,
            )
        )
    landmark_root = compute_subtree_hash(leaf_hashes)
    inclusion_path = compute_inclusion_proof(leaf_index, leaf_hashes)
    mtc_proof_bytes = encode_mtc_proof_tls(
        0, batch_size, inclusion_path, extensions=serial_bytes
    )

    # 4b. Sign the FidoMtcSubtreeCheckpoint with the active CA (LMS Intermediate CA or ML-DSA-87 Root CA)
    checkpoint_bytes = encode_mtc_subtree_checkpoint(
        ca_id, args.log_number, 0, batch_size, landmark_root
    )
    ta_out_path = os.path.join(ent_dir, "mtc_trust_anchor.json")
    checkpoint_sig = None
    if args.ca_type == "lms":
        if args.reuse_key and os.path.exists(ta_out_path):
            try:
                with open(ta_out_path, "r", encoding="utf-8") as tf:
                    existing_ta = json.load(tf)
                st0 = existing_ta["subtrees"][0]
                if st0.get("alg") == -46:
                    cand_sig = b64url_decode(st0["signature"])
                    if lms_mod.verify_hss_lms_signature(int_hss_pub, checkpoint_bytes, cand_sig):
                        checkpoint_sig = cand_sig
            except Exception:
                checkpoint_sig = None
        if checkpoint_sig is None:
            _, checkpoint_sig = int_ca.sign_hss(checkpoint_bytes, explicit_q=5)
    else:
        checkpoint_sig = sign_and_verify_subtree_checkpoint(
            root_key_path, root_cert_path, checkpoint_bytes
        )

    mtc_cert_map = {
        "caId": ca_id,
        "serial": mtc_serial,
        "notBefore": not_before,
        "notAfter": not_after,
        "mtcProof": mtc_proof_bytes,
    }
    if args.fw_version is not None:
        mtc_cert_map["firmwareVersion"] = args.fw_version
    provisioned_mtc = {
        "fmt": "mtc",
        "x5c": cert_der,
        "mtcCert": mtc_cert_map,
    }
    provisioned_cbor = cbor_encode(provisioned_mtc)

    # 5. Write provisioned_enterprise_attestation.cbor, mtc_trust_anchor.json, and mtc_enterprise_info.json
    cbor_out_path = os.path.join(ent_dir, "provisioned_enterprise_attestation.cbor")
    with open(cbor_out_path, "wb") as f:
        f.write(provisioned_cbor)

    trust_anchor = {
        "caId": b64url_encode(ca_id),
        "hashAlg": "sha-256",
        "maxBatchWindow": not_after - not_before,
        "subtrees": [
            {
                "logNumber": args.log_number,
                "start": 0,
                "end": batch_size,
                "rootHash": b64url_encode(landmark_root),
                "alg": root_cose_alg,
                "signature": b64url_encode(checkpoint_sig),
            }
        ],
        "revokedSerials": [],
        "batchKeys": [],
    }
    with open(ta_out_path, "w", encoding="utf-8") as f:
        json.dump(trust_anchor, f, indent=2)

    # Also sign the Non-Enterprise MTC & X.509 batch keys subtree checkpoint in metadata/mtc_batch_trust_anchor.json if present
    batch_ta_path = os.path.join(os.path.dirname(ent_dir), "metadata", "mtc_batch_trust_anchor.json")
    if os.path.exists(batch_ta_path):
        with open(batch_ta_path, "r", encoding="utf-8") as btf:
            batch_ta = json.load(btf)
        batch_ca_id = b64url_decode(batch_ta["caId"])
        for st in batch_ta.get("subtrees", []):
            st_cp = encode_mtc_subtree_checkpoint(
                batch_ca_id,
                int(st["logNumber"]),
                int(st["start"]),
                int(st["end"]),
                b64url_decode(st["rootHash"]),
            )
            st_sig = None
            if args.ca_type == "lms":
                if args.reuse_key and st.get("alg") == -46 and "signature" in st:
                    cand = b64url_decode(st["signature"])
                    if lms_mod.verify_hss_lms_signature(int_hss_pub, st_cp, cand):
                        st_sig = cand
                if st_sig is None:
                    _, st_sig = int_ca.sign_hss(st_cp, explicit_q=4)
            else:
                st_sig = sign_and_verify_subtree_checkpoint(
                    root_key_path, root_cert_path, st_cp
                )
            st["alg"] = root_cose_alg
            st["signature"] = b64url_encode(st_sig)
        with open(batch_ta_path, "w", encoding="utf-8") as btf:
            json.dump(batch_ta, btf, indent=2)
            btf.write("\n")

    active_root_alg_label = "HSS-LMS (LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8)" if args.ca_type == "lms" else args.root_alg
    info_json = {
        "description": "Fidont Enterprise Single-Device Attestation Key, X.509 Certificate, and MTC Info",
        "algorithm": args.alg,
        "coseAlg": cose_alg,
        "aaguid": str(aaguid_obj),
        "serialNumber": args.serial,
        "rootCaCertificate": {
            "algorithm": active_root_alg_label,
            "coseAlg": root_cose_alg,
            "pemFile": os.path.relpath(root_cert_path, ent_dir),
            "privateKeyFile": os.path.relpath(root_key_path, ent_dir),
            "derLengthBytes": len(root_cert_der),
            "derBase64": base64.b64encode(root_cert_der).decode("ascii"),
        },
        "rootCaCertificateEs384": {
            "algorithm": "ES384",
            "coseAlg": -35,
            "pemFile": "enterprise_root_ca_es384.pem",
            "privateKeyFile": "enterprise_root_ca_es384.key",
            "derLengthBytes": len(es384_root_cert_der),
            "derBase64": base64.b64encode(es384_root_cert_der).decode("ascii"),
        },
        "x509Certificate": {
            "pemFile": "fidont_cert.pem",
            "privateKeyFile": "fidont.key",
            "signedBy": os.path.relpath(root_cert_path, ent_dir),
            "derLengthBytes": len(cert_der),
            "fidoAaguidExtensionOid": FIDO_AAGUID_OID,
            "fidoFirmwareVersionExtension": {
                "oid": FIDO_FWVERSION_OID,
                "name": "id-fido-gen-ce-fwversion",
                "critical": False,
                "asn1Type": "OCTET STRING",
                "value": args.fw_version,
                "derHex": fido_fwversion_ext_der.hex(),
            },
            "fidoSerialNumberExtension": {
                "oid": FIDO_SERIAL_OID,
                "name": "id-fido-gen-ce-sernum",
                "critical": False,
                "asn1Type": "OCTET STRING",
                "value": args.serial,
                "derHex": fido_serial_ext_der.hex(),
            },
        },
        "mtcInfo": {
            "caIdHex": ca_id.hex(),
            "caIdB64Url": b64url_encode(ca_id),
            "logNumber": args.log_number,
            "leafIndex": leaf_index,
            "batchSize": batch_size,
            "mtcSerial": mtc_serial,
            "mtcSerialHex": f"0x{mtc_serial:016x}",
            "notBefore": not_before,
            "notAfter": not_after,
            "firmwareVersion": args.fw_version,
            "cosePublicKeyB64Url": b64url_encode(canonical_cose_pk),
            "pubKeyHashHex": pub_key_hash.hex(),
            "leafHashHex": leaf_hashes[leaf_index].hex(),
            "rootHashB64Url": b64url_encode(landmark_root),
            "subtreeCheckpointHex": checkpoint_bytes.hex(),
            "subtreeSignatureAlg": root_cose_alg,
            "subtreeSignatureLengthBytes": len(checkpoint_sig),
            "mtcProofLengthBytes": len(mtc_proof_bytes),
            "mtcProofB64Url": b64url_encode(mtc_proof_bytes),
            "provisionedCborFile": "provisioned_enterprise_attestation.cbor",
            "provisionedCborLengthBytes": len(provisioned_cbor),
        },
        "mtcTrustAnchor": trust_anchor,
        "enterpriseInventoryManifest": {
            "caId": b64url_encode(ca_id),
            "batchKeys": [
                {
                    "serial": mtc_serial,
                    "alg": cose_alg,
                    "notBefore": not_before,
                    "notAfter": not_after,
                    "firmwareVersion": args.fw_version,
                    "deviceSerial": args.serial,
                    "coseKey": b64url_encode(canonical_cose_pk),
                }
            ],
        },
    }
    info_out_path = os.path.join(ent_dir, "mtc_enterprise_info.json")
    with open(info_out_path, "w", encoding="utf-8") as f:
        json.dump(info_json, f, indent=2)

    print(f"[OK] Generated/Verified Enterprise CA ({active_root_alg_label} + ES384) & signed Enterprise X.509 cert ({args.alg}) in {ent_dir}")
    print(f"     FIDO Serial Number ({FIDO_SERIAL_OID}): \"{args.serial}\" (DER OCTET STRING: {fido_serial_ext_der.hex()})")
    print(f"     PQ CA DER: {len(root_cert_der)} B | ES384 Root CA DER: {len(es384_root_cert_der)} B | Enterprise X.509 DER: {len(cert_der)} B")
    print(f"     Subtree checkpoint signed by PQ CA ({active_root_alg_label}, alg={root_cose_alg}): {len(checkpoint_sig)} B signature")
    print(f"     Provisioned dual (mtcCert + x5c) CBOR size: {len(provisioned_cbor)} B")
    print(f"     MTC rootHash: {b64url_encode(landmark_root)}")


if __name__ == "__main__":
    main()
