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
"""Generates RFC 8554 / NIST SP 800-208 HSS/LMS Root CA, Pre-Published MDS Intermediate CAs,
and LMS-signed X.509 Batch & Enterprise Certificates over ML-DSA (-48, -49, -50) batch keys."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import secrets
import struct
import subprocess
import uuid

# ============================================================================
# 1. RFC 8554 / NIST SP 800-208 (SHA256_M32 / N32) Constants & Parameter Sets
# ============================================================================

# Domain separation 16-bit big-endian constants (RFC 8554 §§3.2, 5.3)
D_PBLC = b"\x80\x80"
D_MESG = b"\x81\x81"
D_LEAF = b"\x82\x82"
D_INTR = b"\x83\x83"

# LM-OTS Parameter Sets (RFC 8554 §4.1 / NIST SP 800-208 Table 1):
# typecode -> (name, n, w, p, ls)
LMOTS_PARAMS = {
    1: ("LMOTS_SHA256_N32_W1", 32, 1, 265, 7),
    2: ("LMOTS_SHA256_N32_W2", 32, 2, 133, 6),
    3: ("LMOTS_SHA256_N32_W4", 32, 4, 67, 4),
    4: ("LMOTS_SHA256_N32_W8", 32, 8, 34, 0),
}

# LMS Parameter Sets (RFC 8554 §5.1 / NIST SP 800-208 Table 3):
# typecode -> (name, m, h)
LMS_PARAMS = {
    5: ("LMS_SHA256_M32_H5", 32, 5),
    6: ("LMS_SHA256_M32_H10", 32, 10),
    7: ("LMS_SHA256_M32_H15", 32, 15),
    8: ("LMS_SHA256_M32_H20", 32, 20),
    9: ("LMS_SHA256_M32_H25", 32, 25),
}

COSE_ALG_HSS_LMS = -46  # RFC 8778 COSE Algorithm ID for HSS-LMS

# OID id-alg-hss-lms-hashsig = 1.2.840.113549.1.9.16.3.17 (RFC 8708 / RFC 9708 / RFC 9802)
OID_HSS_LMS_DER = bytes.fromhex("060b2a864886f70d0109100311")

# NIST ML-DSA OIDs (2.16.840.1.101.3.4.3.{17,18,19})
MLDSA_SPECS = {
    "ML-DSA-44": (bytes.fromhex("0609608648016503040311"), -48, 1312),
    "ML-DSA-65": (bytes.fromhex("0609608648016503040312"), -49, 1952),
    "ML-DSA-87": (bytes.fromhex("0609608648016503040313"), -50, 2592),
}

FIDO_AAGUID_OID_DER = bytes.fromhex("060b2b0601040182e51c010104")  # 1.3.6.1.4.1.45724.1.1.4
FIDO_FWVERSION_OID_DER = bytes.fromhex("060b2b0601040182e51c010103")  # 1.3.6.1.4.1.45724.1.1.3
FIDO_SERIAL_OID_DER = bytes.fromhex("060b2b0601040182e51c010102")  # 1.3.6.1.4.1.45724.1.1.2

FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT = b"FIDO-MTC-SUBTREE-CHECKPOINT-V1\x00\x00"


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


# ============================================================================
# 2. RFC 8554 / NIST SP 800-208 HSS/LMS Implementation
# ============================================================================


def u32str(v: int) -> bytes:
    return struct.pack(">I", v)


def u16str(v: int) -> bytes:
    return struct.pack(">H", v)


def u8str(v: int) -> bytes:
    return struct.pack("B", v)


def coef(s: bytes, i: int, w: int) -> int:
    """RFC 8554 §3.1.3: Returns the i-th w-bit value of byte string s."""
    if w == 8:
        return s[i]
    if w == 4:
        b = s[i >> 1]
        return (b >> 4) & 0x0F if (i & 1) == 0 else b & 0x0F
    if w == 2:
        b = s[i >> 2]
        shift = 6 - 2 * (i & 3)
        return (b >> shift) & 0x03
    if w == 1:
        b = s[i >> 3]
        shift = 7 - (i & 7)
        return (b >> shift) & 0x01
    raise ValueError(f"Unsupported w={w}")


def cksm(q_hash: bytes, w: int, n: int = 32, ls: int = 0) -> int:
    """RFC 8554 §4.4: Computes 16-bit Winternitz checksum over n-byte hash Q."""
    total = 0
    max_digit = (1 << w) - 1
    num_digits = (8 * n) // w
    for i in range(num_digits):
        total += max_digit - coef(q_hash, i, w)
    return (total << ls) & 0xFFFF


def lmots_derive_x_i(tree_id: bytes, q: int, i: int, master_seed: bytes) -> bytes:
    """NIST SP 800-208 Appendix A pseudorandom LM-OTS secret key derivation:
    x_q[i] = SHA-256(I || u32str(q) || u16str(i) || u8str(0xFF) || SEED)."""
    return hashlib.sha256(tree_id + u32str(q) + u16str(i) + b"\xff" + master_seed).digest()


def lmots_derive_randomizer_c(tree_id: bytes, q: int, master_seed: bytes) -> bytes:
    """Deterministic per-leaf 32-byte randomizer C derivation (RFC 8554 Appendix A):
    C_q = SHA-256(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)."""
    return hashlib.sha256(tree_id + u32str(q) + b"\xff\xfd\xff" + master_seed).digest()


def lmots_pubkey_hash_k(
    lmots_type: int, tree_id: bytes, q: int, master_seed: bytes
) -> bytes:
    """RFC 8554 §4.3 Algorithm 1: Computes the 32-byte LM-OTS public key hash K_q."""
    _, _, w, p, _ = LMOTS_PARAMS[lmots_type]
    max_steps = (1 << w) - 1
    iq_prefix = tree_id + u32str(q)
    z_list = bytearray()
    for i in range(p):
        tmp = lmots_derive_x_i(tree_id, q, i, master_seed)
        chain_prefix = iq_prefix + u16str(i)
        for j in range(max_steps):
            tmp = hashlib.sha256(chain_prefix + bytes([j]) + tmp).digest()
        z_list.extend(tmp)
    return hashlib.sha256(iq_prefix + D_PBLC + bytes(z_list)).digest()


def lmots_sign(
    lmots_type: int, tree_id: bytes, q: int, master_seed: bytes, message: bytes
) -> bytes:
    """RFC 8554 §4.5 Algorithm 3: Generates an LM-OTS signature over message."""
    _, n, w, p, ls = LMOTS_PARAMS[lmots_type]
    c_rand = lmots_derive_randomizer_c(tree_id, q, master_seed)
    iq_prefix = tree_id + u32str(q)
    q_hash = hashlib.sha256(iq_prefix + D_MESG + c_rand + message).digest()
    q_with_cksm = q_hash + u16str(cksm(q_hash, w, n, ls))

    sig = bytearray(u32str(lmots_type) + c_rand)
    for i in range(p):
        a = coef(q_with_cksm, i, w)
        tmp = lmots_derive_x_i(tree_id, q, i, master_seed)
        chain_prefix = iq_prefix + u16str(i)
        for j in range(a):
            tmp = hashlib.sha256(chain_prefix + bytes([j]) + tmp).digest()
        sig.extend(tmp)
    return bytes(sig)


def lmots_sig_to_pubkey_kc(
    tree_id: bytes, q: int, sig: bytes, message: bytes
) -> tuple[int, bytes]:
    """RFC 8554 §4.6 Algorithm 4b: Computes candidate LM-OTS public key hash Kc from signature."""
    if len(sig) < 4:
        raise ValueError("LM-OTS signature too short.")
    lmots_type = struct.unpack(">I", sig[:4])[0]
    if lmots_type not in LMOTS_PARAMS:
        raise ValueError(f"Unsupported LM-OTS typecode: {lmots_type}")
    _, n, w, p, ls = LMOTS_PARAMS[lmots_type]
    expected_len = 4 + n + p * n
    if len(sig) != expected_len:
        raise ValueError(f"Invalid LM-OTS signature length {len(sig)} != {expected_len}")

    c_rand = sig[4 : 4 + n]
    iq_prefix = tree_id + u32str(q)
    q_hash = hashlib.sha256(iq_prefix + D_MESG + c_rand + message).digest()
    q_with_cksm = q_hash + u16str(cksm(q_hash, w, n, ls))

    max_digit = (1 << w) - 1
    z_list = bytearray()
    offset = 4 + n
    for i in range(p):
        a = coef(q_with_cksm, i, w)
        tmp = sig[offset : offset + n]
        offset += n
        chain_prefix = iq_prefix + u16str(i)
        for j in range(a, max_digit):
            tmp = hashlib.sha256(chain_prefix + bytes([j]) + tmp).digest()
        z_list.extend(tmp)
    kc = hashlib.sha256(iq_prefix + D_PBLC + bytes(z_list)).digest()
    return lmots_type, kc


class StatefulHssLmsCa:
    """Stateful L=1 HSS/LMS Certificate Authority (RFC 8554 / NIST SP 800-208)."""

    def __init__(
        self,
        lms_type: int,
        lmots_type: int,
        tree_id: bytes,
        master_seed: bytes,
        tree_nodes: list[bytes],
        next_q: int = 0,
        state_path: str | None = None,
    ):
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        self.tree_id = tree_id
        self.master_seed = master_seed
        self.tree_nodes = tree_nodes  # 1-indexed array of length 2^(h+1)
        self.next_q = next_q
        self.state_path = state_path
        _, _, self.h = LMS_PARAMS[lms_type]
        self.max_q = 1 << self.h

    @classmethod
    def generate(
        cls,
        lms_type: int = 5,
        lmots_type: int = 4,
        state_path: str | None = None,
        deterministic_seed: bytes | None = None,
    ) -> StatefulHssLmsCa:
        if lms_type not in LMS_PARAMS:
            raise ValueError(f"Unsupported LMS typecode {lms_type}")
        if lmots_type not in LMOTS_PARAMS:
            raise ValueError(f"Unsupported LM-OTS typecode {lmots_type}")
        _, _, h = LMS_PARAMS[lms_type]
        if deterministic_seed is not None:
            tree_id = hashlib.sha256(b"LMS-TREE-ID:" + deterministic_seed).digest()[:16]
            master_seed = hashlib.sha256(b"LMS-MASTER-SEED:" + deterministic_seed).digest()
        else:
            tree_id = secrets.token_bytes(16)
            master_seed = secrets.token_bytes(32)

        num_leaves = 1 << h
        tree_nodes = [b""] * (2 * num_leaves)
        # Compute leaves r = 2^h .. 2^(h+1) - 1
        for q in range(num_leaves):
            r = num_leaves + q
            k_q = lmots_pubkey_hash_k(lmots_type, tree_id, q, master_seed)
            tree_nodes[r] = hashlib.sha256(tree_id + u32str(r) + D_LEAF + k_q).digest()
        # Compute interior nodes r = 2^h - 1 down to 1
        for r in range(num_leaves - 1, 0, -1):
            tree_nodes[r] = hashlib.sha256(
                tree_id + u32str(r) + D_INTR + tree_nodes[2 * r] + tree_nodes[2 * r + 1]
            ).digest()

        ca = cls(
            lms_type=lms_type,
            lmots_type=lmots_type,
            tree_id=tree_id,
            master_seed=master_seed,
            tree_nodes=tree_nodes,
            next_q=0,
            state_path=state_path,
        )
        if state_path:
            ca.save()
        return ca

    def save(self) -> None:
        if not self.state_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        lms_name, _, h = LMS_PARAMS[self.lms_type]
        lmots_name, _, _, _, _ = LMOTS_PARAMS[self.lmots_type]
        data = {
            "levels": 1,
            "lmsType": self.lms_type,
            "lmsName": lms_name,
            "lmotsType": self.lmots_type,
            "lmotsName": lmots_name,
            "height": h,
            "maxLeaves": self.max_q,
            "nextLeafQ": self.next_q,
            "remainingLeaves": self.max_q - self.next_q,
            "treeIdHex": self.tree_id.hex(),
            "masterSeedHex": self.master_seed.hex(),
            "rootHashHex": self.tree_nodes[1].hex(),
            "hssPublicKeyHex": self.hss_public_key_bytes().hex(),
            "treeNodesHex": [n.hex() for n in self.tree_nodes[1:]],
        }
        tmp_path = self.state_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, self.state_path)

    @classmethod
    def load(cls, state_path: str) -> StatefulHssLmsCa:
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        tree_nodes = [b""] + [bytes.fromhex(x) for x in data["treeNodesHex"]]
        return cls(
            lms_type=int(data["lmsType"]),
            lmots_type=int(data["lmotsType"]),
            tree_id=bytes.fromhex(data["treeIdHex"]),
            master_seed=bytes.fromhex(data["masterSeedHex"]),
            tree_nodes=tree_nodes,
            next_q=int(data["nextLeafQ"]),
            state_path=state_path,
        )

    def lms_public_key_bytes(self) -> bytes:
        """56-byte RFC 8554 §5.3 LMS public key: u32str(lms_type) || u32str(lmots_type) || I || T[1]."""
        return (
            u32str(self.lms_type)
            + u32str(self.lmots_type)
            + self.tree_id
            + self.tree_nodes[1]
        )

    def hss_public_key_bytes(self) -> bytes:
        """60-byte RFC 8554 §6.1 HSS public key (L=1): u32str(1) || lms_public_key_bytes()."""
        return u32str(1) + self.lms_public_key_bytes()

    def sign_hss(self, message: bytes, explicit_q: int | None = None) -> tuple[int, bytes]:
        """Signs message using the next available leaf q (or explicit_q for idempotent re-runs),
        persisting the incremented next_q counter before returning (q, 1296-byte HSS signature)."""
        if explicit_q is not None:
            q = explicit_q
        else:
            q = self.next_q
        if q < 0 or q >= self.max_q:
            raise RuntimeError(
                f"LMS CA leaf exhaustion: requested q={q}, max_q={self.max_q}"
            )
        if q >= self.next_q:
            self.next_q = q + 1
            self.save()

        ots_sig = lmots_sign(self.lmots_type, self.tree_id, q, self.master_seed, message)
        num_leaves = 1 << self.h
        node_idx = num_leaves + q
        path = bytearray()
        for _ in range(self.h):
            sibling_idx = node_idx ^ 1
            path.extend(self.tree_nodes[sibling_idx])
            node_idx >>= 1

        lms_sig = u32str(q) + ots_sig + u32str(self.lms_type) + bytes(path)
        hss_sig = u32str(0) + lms_sig  # Nspk = L - 1 = 0
        # Always self-verify before returning
        if not verify_hss_lms_signature(self.hss_public_key_bytes(), message, hss_sig):
            raise RuntimeError("Internal error: generated HSS/LMS signature failed self-verification!")
        return q, hss_sig


def verify_hss_lms_signature(hss_pub_key: bytes, message: bytes, hss_sig: bytes) -> bool:
    """RFC 8554 §§5.4.2, 6.3: Verifies an L=1 HSS/LMS signature against a 60-byte HSS public key."""
    try:
        # Unwrap optional OCTET STRING if present
        if len(hss_pub_key) == 62 and hss_pub_key[:2] == b"\x04\x3c":
            hss_pub_key = hss_pub_key[2:]
        if len(hss_pub_key) != 60:
            return False
        levels, pub_lms_type, pub_lmots_type = struct.unpack(">III", hss_pub_key[:12])
        if levels != 1 or pub_lms_type not in LMS_PARAMS or pub_lmots_type not in LMOTS_PARAMS:
            return False
        tree_id = hss_pub_key[12:28]
        root_hash = hss_pub_key[28:60]
        _, m, h = LMS_PARAMS[pub_lms_type]
        _, n, _, p, _ = LMOTS_PARAMS[pub_lmots_type]

        ots_sig_len = 4 + n + p * n
        expected_sig_len = 4 + 4 + ots_sig_len + 4 + h * m
        if len(hss_sig) != expected_sig_len:
            return False

        nspk, q = struct.unpack(">II", hss_sig[:8])
        if nspk != 0 or q >= (1 << h):
            return False

        ots_sig = hss_sig[8 : 8 + ots_sig_len]
        sig_lms_type = struct.unpack(">I", hss_sig[8 + ots_sig_len : 12 + ots_sig_len])[0]
        if sig_lms_type != pub_lms_type:
            return False

        sig_lmots_type, kc = lmots_sig_to_pubkey_kc(tree_id, q, ots_sig, message)
        if sig_lmots_type != pub_lmots_type:
            return False

        node_num = (1 << h) + q
        tmp = hashlib.sha256(tree_id + u32str(node_num) + D_LEAF + kc).digest()
        path_offset = 12 + ots_sig_len
        for _ in range(h):
            path_node = hss_sig[path_offset : path_offset + m]
            path_offset += m
            if (node_num & 1) == 1:
                tmp = hashlib.sha256(
                    tree_id + u32str(node_num >> 1) + D_INTR + path_node + tmp
                ).digest()
            else:
                tmp = hashlib.sha256(
                    tree_id + u32str(node_num >> 1) + D_INTR + tmp + path_node
                ).digest()
            node_num >>= 1
        return tmp == root_hash
    except Exception:
        return False


# ============================================================================
# 3. ASN.1 DER X.509v3 Builder for HSS/LMS and ML-DSA Certificates
# ============================================================================


def der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    if length <= 0xFFFF:
        return struct.pack(">BH", 0x82, length)
    return struct.pack(">BBBB", 0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF)


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def der_sequence(items: list[bytes]) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_set(items: list[bytes]) -> bytes:
    return der_tlv(0x31, b"".join(items))


def der_integer(val: int) -> bytes:
    if val == 0:
        return b"\x02\x01\x00"
    b = val.to_bytes((val.bit_length() + 8) // 8, "big")
    return der_tlv(0x02, b)


def der_octet_string(b: bytes) -> bytes:
    return der_tlv(0x04, b)


def der_bit_string(b: bytes) -> bytes:
    return der_tlv(0x03, b"\x00" + b)


def der_utf8_string(s: str) -> bytes:
    return der_tlv(0x0C, s.encode("utf-8"))


def der_printable_string(s: str) -> bytes:
    return der_tlv(0x13, s.encode("ascii"))


def der_utctime(dt: datetime.datetime) -> bytes:
    s = dt.strftime("%y%m%d%H%M%SZ").encode("ascii")
    return der_tlv(0x17, s)


def der_explicit(tag_num: int, inner: bytes) -> bytes:
    return der_tlv(0xA0 | tag_num, inner)


def der_rdn(oid_der: bytes, val_der: bytes) -> bytes:
    return der_set([der_sequence([oid_der, val_der])])


def der_name(cn: str, o: str = "John Bradley", ou: str = "Authenticator Attestation", c: str = "CA") -> bytes:
    oid_c = bytes.fromhex("0603550406")   # 2.5.4.6 countryName
    oid_o = bytes.fromhex("060355040a")   # 2.5.4.10 organizationName
    oid_ou = bytes.fromhex("060355040b")  # 2.5.4.11 organizationalUnitName
    oid_cn = bytes.fromhex("0603550403")  # 2.5.4.3 commonName
    return der_sequence(
        [
            der_rdn(oid_c, der_printable_string(c)),
            der_rdn(oid_o, der_utf8_string(o)),
            der_rdn(oid_ou, der_utf8_string(ou)),
            der_rdn(oid_cn, der_utf8_string(cn)),
        ]
    )


def der_ext(oid_der: bytes, critical: bool, val_bytes: bytes) -> bytes:
    items = [oid_der]
    if critical:
        items.append(b"\x01\x01\xff")
    items.append(der_octet_string(val_bytes))
    return der_sequence(items)


def der_ext_basic_constraints(is_ca: bool, pathlen: int | None = None) -> bytes:
    oid_bc = bytes.fromhex("0603551d13")  # 2.5.29.19
    inner = []
    if is_ca:
        inner.append(b"\x01\x01\xff")
        if pathlen is not None:
            inner.append(der_integer(pathlen))
    return der_ext(oid_bc, True, der_sequence(inner))


def der_ext_key_usage_ca() -> bytes:
    oid_ku = bytes.fromhex("0603551d0f")  # 2.5.29.15
    # keyCertSign (bit 5) | cRLSign (bit 6) -> 0x06 with 1 unused bit -> 03 02 01 06
    return der_ext(oid_ku, True, b"\x03\x02\x01\x06")


def der_ext_key_usage_digital_sig() -> bytes:
    oid_ku = bytes.fromhex("0603551d0f")  # 2.5.29.15
    # digitalSignature (bit 0) -> 0x80 with 7 unused bits -> 03 02 07 80
    return der_ext(oid_ku, True, b"\x03\x02\x07\x80")


def der_ext_ski(pub_key_bytes: bytes) -> tuple[bytes, bytes]:
    oid_ski = bytes.fromhex("0603551d0e")  # 2.5.29.14
    key_id = hashlib.sha1(pub_key_bytes).digest()
    return key_id, der_ext(oid_ski, False, der_octet_string(key_id))


def der_ext_aki(issuer_key_id: bytes) -> bytes:
    oid_aki = bytes.fromhex("0603551d23")  # 2.5.29.35
    # AuthorityKeyIdentifier ::= SEQUENCE { [0] IMPLICIT KeyIdentifier }
    key_id_implicit = der_tlv(0x80, issuer_key_id)
    return der_ext(oid_aki, False, der_sequence([key_id_implicit]))


def der_spki_hss_lms(hss_pub_key_60b: bytes) -> bytes:
    """RFC 8708 / RFC 9708 / RFC 9802 SubjectPublicKeyInfo for id-alg-hss-lms-hashsig."""
    alg_id = der_sequence([OID_HSS_LMS_DER])
    return der_sequence([alg_id, der_bit_string(hss_pub_key_60b)])


def der_spki_mldsa(alg_name: str, raw_pub_key: bytes) -> bytes:
    oid_der, _, expected_len = MLDSA_SPECS[alg_name]
    if len(raw_pub_key) != expected_len:
        raise ValueError(f"{alg_name} public key length {len(raw_pub_key)} != {expected_len}")
    alg_id = der_sequence([oid_der])
    return der_sequence([alg_id, der_bit_string(raw_pub_key)])


def build_and_sign_lms_x509_cert(
    signer_ca: StatefulHssLmsCa,
    serial_int: int,
    issuer_name_der: bytes,
    subject_name_der: bytes,
    not_before_dt: datetime.datetime,
    not_after_dt: datetime.datetime,
    spki_der: bytes,
    extensions_list: list[bytes],
    explicit_q: int | None = None,
) -> tuple[int, bytes, str]:
    """Builds an X.509v3 TBSCertificate, signs it with signer_ca using HSS/LMS (OID 1.2.840.113549.1.9.16.3.17),
    and returns (leaf_q, cert_der_bytes, cert_pem_str)."""
    sig_alg_id = der_sequence([OID_HSS_LMS_DER])
    validity_der = der_sequence([der_utctime(not_before_dt), der_utctime(not_after_dt)])
    tbs_items = [
        der_explicit(0, der_integer(2)),  # version v3 (2)
        der_integer(serial_int),
        sig_alg_id,
        issuer_name_der,
        validity_der,
        subject_name_der,
        spki_der,
        der_explicit(3, der_sequence(extensions_list)),
    ]
    tbs_der = der_sequence(tbs_items)
    q, hss_sig = signer_ca.sign_hss(tbs_der, explicit_q=explicit_q)
    cert_der = der_sequence([tbs_der, sig_alg_id, der_bit_string(hss_sig)])

    b64 = base64.b64encode(cert_der).decode("ascii")
    pem_lines = (
        ["-----BEGIN CERTIFICATE-----"]
        + [b64[i : i + 64] for i in range(0, len(b64), 64)]
        + ["-----END CERTIFICATE-----", ""]
    )
    return q, cert_der, "\n".join(pem_lines)


def verify_lms_x509_cert_der(cert_der: bytes, issuer_hss_pub_key_60b: bytes) -> bool:
    """Extracts TBSCertificate and signatureValue from an X.509 DER certificate and verifies HSS/LMS signature."""
    # Parse outer SEQUENCE
    if cert_der[0] != 0x30:
        return False
    idx = 1
    if cert_der[idx] & 0x80:
        n_len = cert_der[idx] & 0x7F
        idx += 1 + n_len
    else:
        idx += 1
    # First element is TBSCertificate SEQUENCE
    if cert_der[idx] != 0x30:
        return False
    tbs_start = idx
    idx += 1
    if cert_der[idx] & 0x80:
        n_len = cert_der[idx] & 0x7F
        tbs_body_len = int.from_bytes(cert_der[idx + 1 : idx + 1 + n_len], "big")
        idx += 1 + n_len
    else:
        tbs_body_len = cert_der[idx]
        idx += 1
    tbs_end = idx + tbs_body_len
    tbs_der = cert_der[tbs_start:tbs_end]

    # Next is signatureAlgorithm SEQUENCE (30 0d 06 0b 2a 86 48 86 f7 0d 01 09 10 03 11)
    sig_alg_expected = der_sequence([OID_HSS_LMS_DER])
    if cert_der[tbs_end : tbs_end + len(sig_alg_expected)] != sig_alg_expected:
        return False
    sig_pos = tbs_end + len(sig_alg_expected)
    if cert_der[sig_pos] != 0x03:
        return False
    sig_pos += 1
    if cert_der[sig_pos] & 0x80:
        n_len = cert_der[sig_pos] & 0x7F
        sig_bitstr_len = int.from_bytes(cert_der[sig_pos + 1 : sig_pos + 1 + n_len], "big")
        sig_pos += 1 + n_len
    else:
        sig_bitstr_len = cert_der[sig_pos]
        sig_pos += 1
    if cert_der[sig_pos] != 0x00:
        return False
    hss_sig = cert_der[sig_pos + 1 : sig_pos + sig_bitstr_len]
    return verify_hss_lms_signature(issuer_hss_pub_key_60b, tbs_der, hss_sig)


# ============================================================================
# 4. Extract ML-DSA Public Key from Existing Key/CSR/Cert
# ============================================================================


def extract_mldsa_pubkey_from_key_or_cert(key_path: str, cert_path: str | None = None) -> tuple[str, int, bytes]:
    """Extracts (alg_name, cose_alg, raw_pub_key_bytes) from an OpenSSL ML-DSA private key or cert."""
    pub_der = subprocess.check_output(
        ["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"]
    )
    for alg_name, (oid_der, cose_alg, pk_len) in MLDSA_SPECS.items():
        bit_str_hdr = bytes([0x03, 0x82, ((pk_len + 1) >> 8) & 0xFF, (pk_len + 1) & 0xFF, 0x00])
        pattern = oid_der + bit_str_hdr
        idx = pub_der.find(pattern)
        if idx != -1 and len(pub_der) >= idx + len(pattern) + pk_len:
            start = idx + len(pattern)
            return alg_name, cose_alg, pub_der[start : start + pk_len]
    raise ValueError(f"Could not extract ML-DSA public key from {key_path}")


def extract_hss_pubkey_from_cert_der(cert_der: bytes) -> bytes | None:
    """Extracts the 60-byte HSS public key from an X.509 DER certificate's SubjectPublicKeyInfo."""
    pattern = der_sequence([OID_HSS_LMS_DER]) + b"\x03\x3d\x00"
    idx = cert_der.find(pattern)
    if idx != -1 and len(cert_der) >= idx + len(pattern) + 60:
        start = idx + len(pattern)
        return cert_der[start : start + 60]
    return None


# ============================================================================
# 5. MTC Helpers for Signing Subtree Checkpoints with LMS CA
# ============================================================================


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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
    out = bytearray(FIDO_MTC_SUBTREE_CHECKPOINT_CONTEXT)
    out.extend(struct.pack(">H", len(ca_id)))
    out.extend(ca_id)
    out.extend(struct.pack(">H", log_number))
    out.extend(start.to_bytes(8, "big")[2:8])
    out.extend(end.to_bytes(8, "big")[2:8])
    out.extend(root_hash)
    return bytes(out)


# ============================================================================
# 6. Main CLI Orchestrator
# ============================================================================


def generate_lms_hierarchy_and_batch_certs(
    repo_root: str,
    num_intermediates: int = 4,
    active_intermediate_idx: int = 0,
    enterprise_serial: str = "123456",
    fw_version: int | None = None,
    force_regen_ca: bool = False,
    update_mds: bool = True,
) -> dict:
    if fw_version is None:
        fw_version = read_opensk_firmware_version(repo_root)
    lms_dir = os.path.join(repo_root, "crypto_data_lms")
    root_dir = os.path.join(lms_dir, "root_ca")
    int_dir = os.path.join(lms_dir, "intermediates")
    os.makedirs(root_dir, exist_ok=True)
    os.makedirs(int_dir, exist_ok=True)

    aaguid_path = os.path.join(repo_root, "crypto_data", "aaguid.txt")
    with open(aaguid_path, "r", encoding="utf-8") as f:
        aaguid_obj = uuid.UUID(f.read().strip())
    aaguid_bytes = aaguid_obj.bytes

    # Fixed validity window matching Fidont certs (2026-10-18 to 2036-10-15 UTC)
    not_before_dt = datetime.datetime(2026, 10, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)
    not_after_dt = datetime.datetime(2036, 10, 15, 0, 0, 0, tzinfo=datetime.timezone.utc)

    # ------------------------------------------------------------------------
    # Step 1: Parent LMS Root CA (L=1, LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8)
    # ------------------------------------------------------------------------
    root_state_path = os.path.join(root_dir, "lms_root_ca.state.json")
    root_pem_path = os.path.join(root_dir, "lms_root_ca.pem")
    root_der_path = os.path.join(root_dir, "lms_root_ca.der")

    if not force_regen_ca and os.path.exists(root_state_path) and os.path.exists(root_der_path):
        root_ca = StatefulHssLmsCa.load(root_state_path)
        with open(root_der_path, "rb") as f:
            root_cert_der = f.read()
        with open(root_pem_path, "r", encoding="utf-8") as f:
            root_cert_pem = f.read()
        root_ski = hashlib.sha1(root_ca.hss_public_key_bytes()).digest()
    else:
        root_ca = StatefulHssLmsCa.generate(
            lms_type=5,
            lmots_type=4,
            state_path=root_state_path,
            deterministic_seed=b"Fidont-LMS-Root-CA-v1-" + aaguid_bytes,
        )
        root_dn = der_name("Fidont LMS Root CA")
        root_spki = der_spki_hss_lms(root_ca.hss_public_key_bytes())
        root_ski, root_ski_ext = der_ext_ski(root_ca.hss_public_key_bytes())
        root_exts = [
            der_ext_basic_constraints(is_ca=True, pathlen=1),
            der_ext_key_usage_ca(),
            root_ski_ext,
        ]
        _, root_cert_der, root_cert_pem = build_and_sign_lms_x509_cert(
            signer_ca=root_ca,
            serial_int=0x0100,
            issuer_name_der=root_dn,
            subject_name_der=root_dn,
            not_before_dt=not_before_dt,
            not_after_dt=not_after_dt,
            spki_der=root_spki,
            extensions_list=root_exts,
            explicit_q=0,
        )
        with open(root_der_path, "wb") as f:
            f.write(root_cert_der)
        with open(root_pem_path, "w", encoding="utf-8") as f:
            f.write(root_cert_pem)

    assert verify_lms_x509_cert_der(root_cert_der, root_ca.hss_public_key_bytes()), (
        "Parent LMS Root CA self-signed certificate verification failed!"
    )
    root_dn = der_name("Fidont LMS Root CA")

    # ------------------------------------------------------------------------
    # Step 2: Pre-Published LMS Intermediate CAs (#0 .. #{num_intermediates-1})
    #         Each is L=1 LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8 (signs 32 batch keys)
    # ------------------------------------------------------------------------
    intermediates: list[tuple[StatefulHssLmsCa, bytes, str, bytes, bytes]] = []
    for k in range(num_intermediates):
        int_state_path = os.path.join(int_dir, f"lms_intermediate_{k}.state.json")
        int_pem_path = os.path.join(int_dir, f"lms_intermediate_{k}.pem")
        int_der_path = os.path.join(int_dir, f"lms_intermediate_{k}.der")
        int_dn = der_name(f"Fidont LMS Intermediate CA #{k}")

        if not force_regen_ca and os.path.exists(int_state_path) and os.path.exists(int_der_path):
            int_ca = StatefulHssLmsCa.load(int_state_path)
            with open(int_der_path, "rb") as f:
                int_cert_der = f.read()
            with open(int_pem_path, "r", encoding="utf-8") as f:
                int_cert_pem = f.read()
            int_ski = hashlib.sha1(int_ca.hss_public_key_bytes()).digest()
        else:
            int_ca = StatefulHssLmsCa.generate(
                lms_type=5,
                lmots_type=4,
                state_path=int_state_path,
                deterministic_seed=f"Fidont-LMS-Intermediate-CA-{k}-v1-".encode("utf-8") + aaguid_bytes,
            )
            int_spki = der_spki_hss_lms(int_ca.hss_public_key_bytes())
            int_ski, int_ski_ext = der_ext_ski(int_ca.hss_public_key_bytes())
            int_exts = [
                der_ext_basic_constraints(is_ca=True, pathlen=0),
                der_ext_key_usage_ca(),
                int_ski_ext,
                der_ext_aki(root_ski),
            ]
            _, int_cert_der, int_cert_pem = build_and_sign_lms_x509_cert(
                signer_ca=root_ca,
                serial_int=0x0200 + k,
                issuer_name_der=root_dn,
                subject_name_der=int_dn,
                not_before_dt=not_before_dt,
                not_after_dt=not_after_dt,
                spki_der=int_spki,
                extensions_list=int_exts,
                explicit_q=k + 1,  # Root leaf q=0 is self-sig; q=1..N sign Intermediates #0..#N-1
            )
            with open(int_der_path, "wb") as f:
                f.write(int_cert_der)
            with open(int_pem_path, "w", encoding="utf-8") as f:
                f.write(int_cert_pem)

        assert verify_lms_x509_cert_der(int_cert_der, root_ca.hss_public_key_bytes()), (
            f"Intermediate CA #{k} certificate failed verification under Parent LMS Root CA!"
        )
        intermediates.append((int_ca, int_cert_der, int_cert_pem, int_dn, int_ski))

    active_int_ca, active_int_der, active_int_pem, active_int_dn, active_int_ski = intermediates[
        active_intermediate_idx
    ]

    # ------------------------------------------------------------------------
    # Step 3: Sign Batch Certificates for each of the ML-DSA Batch Keys
    #         (ML-DSA-44, ML-DSA-65, ML-DSA-87) + Enterprise ML-DSA Key
    # ------------------------------------------------------------------------
    batch_specs = [
        ("crypto_data_mldsa44", "ML-DSA-44", 0, 0x0300, False),
        ("crypto_data_mldsa65", "ML-DSA-65", 1, 0x0301, False),
        ("crypto_data_mldsa87", "ML-DSA-87", 2, 0x0302, False),
        ("crypto_data_enterprise", "ML-DSA-44", 3, 0x0303, True),
    ]

    fido_aaguid_ext = der_ext(
        FIDO_AAGUID_OID_DER, False, der_octet_string(aaguid_bytes)
    )
    fido_fwversion_ext = der_ext(
        FIDO_FWVERSION_OID_DER, False, der_octet_string(struct.pack(">I", fw_version))
    )
    issued_batch_certs = {}

    for dir_name, expected_alg, leaf_q, cert_serial, is_enterprise in batch_specs:
        b_dir = os.path.join(repo_root, dir_name)
        key_path = os.path.join(b_dir, "fidont.key")
        cert_pem_path = os.path.join(b_dir, "fidont_cert.pem")
        cert_der_path = os.path.join(b_dir, "fidont_cert.der")
        lms_backup_pem_path = os.path.join(b_dir, "fidont_lms_cert.pem")
        mldsa_backup_pem_path = os.path.join(b_dir, "fidont_mldsa87ca_cert.pem")

        if not os.path.exists(key_path):
            continue

        # Preserve a backup of the old ML-DSA-87-CA-signed cert if not already backed up
        if os.path.exists(cert_pem_path) and not os.path.exists(mldsa_backup_pem_path):
            with open(cert_pem_path, "rb") as old_f:
                old_bytes = old_f.read()
            if OID_HSS_LMS_DER not in base64.b64decode(
                b"".join(
                    l.strip()
                    for l in old_bytes.splitlines()
                    if l.strip() and not l.strip().startswith(b"-----")
                )
            ):
                with open(mldsa_backup_pem_path, "wb") as bak_f:
                    bak_f.write(old_bytes)

        alg_name, cose_alg, raw_pub = extract_mldsa_pubkey_from_key_or_cert(key_path)
        spki_der = der_spki_mldsa(alg_name, raw_pub)

        subj_cn = "Fidont Enterprise Attestation" if is_enterprise else "Fidont Attestation"
        subj_dn = der_name(subj_cn)
        exts = [
            der_ext_basic_constraints(is_ca=False),
            der_ext_key_usage_digital_sig(),
            der_ext_aki(active_int_ski),
            fido_aaguid_ext,
            fido_fwversion_ext,
        ]
        if is_enterprise:
            serial_utf8 = enterprise_serial.encode("utf-8")
            exts.append(der_ext(FIDO_SERIAL_OID_DER, False, der_octet_string(serial_utf8)))

        used_q, batch_cert_der, batch_cert_pem = build_and_sign_lms_x509_cert(
            signer_ca=active_int_ca,
            serial_int=cert_serial,
            issuer_name_der=active_int_dn,
            subject_name_der=subj_dn,
            not_before_dt=not_before_dt,
            not_after_dt=not_after_dt,
            spki_der=spki_der,
            extensions_list=exts,
            explicit_q=leaf_q,
        )
        assert verify_lms_x509_cert_der(
            batch_cert_der, active_int_ca.hss_public_key_bytes()
        ), f"Batch certificate in {dir_name} failed LMS verification under Intermediate CA #{active_intermediate_idx}!"

        with open(cert_pem_path, "w", encoding="utf-8") as f:
            f.write(batch_cert_pem)
        with open(lms_backup_pem_path, "w", encoding="utf-8") as f:
            f.write(batch_cert_pem)
        with open(cert_der_path, "wb") as f:
            f.write(batch_cert_der)

        issued_batch_certs[dir_name] = {
            "directory": dir_name,
            "subjectAlg": alg_name,
            "coseAlg": cose_alg,
            "subjectPublicKeyBytes": len(raw_pub),
            "signedByIntermediateIndex": active_intermediate_idx,
            "intermediateLeafQ": used_q,
            "certSerialHex": f"0x{cert_serial:04x}",
            "firmwareVersion": fw_version,
            "fidoFirmwareVersionHex": f"{fw_version:08x}",
            "derLengthBytes": len(batch_cert_der),
            "pemFile": cert_pem_path,
        }
        if is_enterprise:
            issued_batch_certs[dir_name]["enterpriseSerial"] = enterprise_serial

    # ------------------------------------------------------------------------
    # Step 4: Sign MTC Subtree Checkpoints (alg: -46 HSS-LMS) & Update MDS JSONs
    # ------------------------------------------------------------------------
    # Use Intermediate CA #0 leaf q=4 for Non-Enterprise MTC subtree ("g5k_AQE")
    # and leaf q=5 for Enterprise MTC subtree ("g5k_AQI")
    es384_root_pem_path = os.path.join(
        repo_root, "crypto_data_enterprise", "enterprise_root_ca_es384.pem"
    )
    es384_root_b64 = None
    if os.path.exists(es384_root_pem_path):
        es384_der = subprocess.check_output(
            ["openssl", "x509", "-in", es384_root_pem_path, "-outform", "DER"]
        )
        es384_root_b64 = base64.b64encode(es384_der).decode("ascii")

    # Build attestationRootCertificates list for FIDO MDS:
    # 1. Pre-published LMS Intermediate CAs (#0 .. #N-1) so RPs can directly verify
    #    1-certificate x5c: [attestnCert] (and/or chain to Parent LMS Root CA)
    # 2. Parent LMS Root CA
    # 3. Classical ES384 Root CA (for non-ML-DSA classical cX5c batch certificate)
    mds_root_certs_b64 = [
        base64.b64encode(int_der).decode("ascii") for (_, int_der, _, _, _) in intermediates
    ]
    mds_root_certs_b64.append(base64.b64encode(root_cert_der).decode("ascii"))
    if es384_root_b64:
        mds_root_certs_b64.append(es384_root_b64)

    if update_mds:
        # Update standalone trust anchor files first
        ta_files = [
            (os.path.join(repo_root, "metadata", "mtc_batch_trust_anchor.json"), 4),
            (os.path.join(repo_root, "crypto_data_enterprise", "mtc_trust_anchor.json"), 5),
        ]
        loaded_tas = {}
        for ta_path, q_idx in ta_files:
            if os.path.exists(ta_path):
                with open(ta_path, "r", encoding="utf-8") as f:
                    ta = json.load(f)
                ca_id_bytes = b64url_decode(ta["caId"])
                for bk in ta.get("batchKeys", []):
                    bk.setdefault("notBefore", int(not_before_dt.timestamp()))
                    bk["notAfter"] = 253402300799
                    bk["firmwareVersion"] = fw_version
                for st in ta.get("subtrees", []):
                    cp_bytes = encode_mtc_subtree_checkpoint(
                        ca_id_bytes,
                        int(st["logNumber"]),
                        int(st["start"]),
                        int(st["end"]),
                        b64url_decode(st["rootHash"]),
                    )
                    _, cp_sig = active_int_ca.sign_hss(cp_bytes, explicit_q=q_idx)
                    st["alg"] = COSE_ALG_HSS_LMS
                    st["signature"] = b64url_encode(cp_sig)
                with open(ta_path, "w", encoding="utf-8") as f:
                    json.dump(ta, f, indent=2)
                    f.write("\n")
                loaded_tas[ta["caId"]] = ta

        # Update all MDS3 metadata JSON files in metadata/
        mds_files = [
            "metadata_mldsa44_mtc.json",
            "metadata_mldsa65_mtc.json",
            "metadata_mldsa87_mtc.json",
            "metadata_mldsa_all_mtc.json",
        ]
        for mds_name in mds_files:
            mds_path = os.path.join(repo_root, "metadata", mds_name)
            if not os.path.exists(mds_path):
                continue
            with open(mds_path, "r", encoding="utf-8") as f:
                mds = json.load(f)
            mds["authenticatorVersion"] = fw_version
            if "authenticatorGetInfo" in mds and isinstance(mds["authenticatorGetInfo"], dict):
                mds["authenticatorGetInfo"]["firmwareVersion"] = fw_version
            mds["attestationRootCertificates"] = mds_root_certs_b64
            for ta in mds.get("mtcTrustAnchors", []):
                ca_id_str = ta.get("caId", "")
                for bk in ta.get("batchKeys", []):
                    bk.setdefault("notBefore", int(not_before_dt.timestamp()))
                    bk["notAfter"] = 253402300799
                    bk["firmwareVersion"] = fw_version
                if ca_id_str in loaded_tas:
                    ta["maxBatchWindow"] = loaded_tas[ca_id_str]["maxBatchWindow"]
                    ta["subtrees"] = loaded_tas[ca_id_str]["subtrees"]
                else:
                    ca_id_bytes = b64url_decode(ca_id_str)
                    q_slot = 4 if ca_id_str == "g5k_AQE" else 5
                    for st in ta.get("subtrees", []):
                        cp_bytes = encode_mtc_subtree_checkpoint(
                            ca_id_bytes,
                            int(st["logNumber"]),
                            int(st["start"]),
                            int(st["end"]),
                            b64url_decode(st["rootHash"]),
                        )
                        _, cp_sig = active_int_ca.sign_hss(cp_bytes, explicit_q=q_slot)
                        st["alg"] = COSE_ALG_HSS_LMS
                        st["signature"] = b64url_encode(cp_sig)
            with open(mds_path, "w", encoding="utf-8") as f:
                json.dump(mds, f, indent=2)
                f.write("\n")

    summary = {
        "aaguid": str(aaguid_obj),
        "lmsParameterSet": "LMS_SHA256_M32_H5 (0x05) + LMOTS_SHA256_N32_W8 (0x04)",
        "x509Oid": "1.2.840.113549.1.9.16.3.17",
        "coseAlg": COSE_ALG_HSS_LMS,
        "rootCa": {
            "subject": "CN=Fidont LMS Root CA, O=John Bradley, OU=Authenticator Attestation, C=CA",
            "publicKeyBytes": len(root_ca.hss_public_key_bytes()),
            "derLengthBytes": len(root_cert_der),
            "nextLeafQ": root_ca.next_q,
            "maxLeaves": root_ca.max_q,
            "pemFile": root_pem_path,
            "stateFile": root_state_path,
        },
        "intermediates": [
            {
                "index": idx,
                "subject": f"CN=Fidont LMS Intermediate CA #{idx}, O=John Bradley, OU=Authenticator Attestation, C=CA",
                "signedByRootLeafQ": idx + 1,
                "publicKeyBytes": len(ca_obj.hss_public_key_bytes()),
                "derLengthBytes": len(c_der),
                "nextLeafQ": ca_obj.next_q,
                "maxLeaves": ca_obj.max_q,
                "pemFile": os.path.join(int_dir, f"lms_intermediate_{idx}.pem"),
                "stateFile": os.path.join(int_dir, f"lms_intermediate_{idx}.state.json"),
            }
            for idx, (ca_obj, c_der, _, _, _) in enumerate(intermediates)
        ],
        "batchCertificates": issued_batch_certs,
    }
    summary_path = os.path.join(lms_dir, "lms_hierarchy_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    return summary


def verify_all_lms_artifacts(repo_root: str) -> None:
    """Verifies the entire LMS Root -> Intermediate -> ML-DSA Batch Cert & MDS Subtree hierarchy."""
    lms_dir = os.path.join(repo_root, "crypto_data_lms")
    root_der_path = os.path.join(lms_dir, "root_ca", "lms_root_ca.der")
    with open(root_der_path, "rb") as f:
        root_der = f.read()
    root_pub = extract_hss_pubkey_from_cert_der(root_der)
    assert root_pub is not None, "Failed to extract HSS public key from Root CA DER"
    assert verify_lms_x509_cert_der(root_der, root_pub), "Root CA self-signature invalid!"
    print(f"[VERIFIED] Parent LMS Root CA self-signed X.509 cert ({len(root_der)} B DER, 60 B HSS pubkey)")

    int_pubs = []
    int_dir = os.path.join(lms_dir, "intermediates")
    for k in sorted(
        int(fn.split("_")[2].split(".")[0])
        for fn in os.listdir(int_dir)
        if fn.startswith("lms_intermediate_") and fn.endswith(".der")
    ):
        int_der_path = os.path.join(int_dir, f"lms_intermediate_{k}.der")
        with open(int_der_path, "rb") as f:
            int_der = f.read()
        assert verify_lms_x509_cert_der(int_der, root_pub), (
            f"Intermediate CA #{k} failed verification under Parent LMS Root CA!"
        )
        int_pub = extract_hss_pubkey_from_cert_der(int_der)
        assert int_pub is not None
        int_pubs.append(int_pub)
        print(
            f"[VERIFIED] Pre-Published LMS Intermediate CA #{k} X.509 cert ({len(int_der)} B DER) under Parent LMS Root CA"
        )

    for dir_name in ["crypto_data_mldsa44", "crypto_data_mldsa65", "crypto_data_mldsa87", "crypto_data_enterprise"]:
        cert_der_path = os.path.join(repo_root, dir_name, "fidont_cert.der")
        if not os.path.exists(cert_der_path):
            continue
        with open(cert_der_path, "rb") as f:
            c_der = f.read()
        matched_int = None
        for idx, ipub in enumerate(int_pubs):
            if verify_lms_x509_cert_der(c_der, ipub):
                matched_int = idx
                break
        assert matched_int is not None, f"{dir_name}/fidont_cert.der failed verification against all LMS Intermediates!"
        print(
            f"[VERIFIED] {dir_name}/fidont_cert.pem ({len(c_der)} B DER) verified under LMS Intermediate CA #{matched_int}"
        )

    mds_path = os.path.join(repo_root, "metadata", "metadata_mldsa_all_mtc.json")
    if os.path.exists(mds_path):
        with open(mds_path, "r", encoding="utf-8") as f:
            mds = json.load(f)
        mds_hss_pubs = []
        for cert_b64 in mds.get("attestationRootCertificates", []):
            c_der = base64.b64decode(cert_b64)
            hpub = extract_hss_pubkey_from_cert_der(c_der)
            if hpub is not None:
                mds_hss_pubs.append(hpub)
        for ta in mds.get("mtcTrustAnchors", []):
            ca_id_str = ta["caId"]
            ca_id_bytes = b64url_decode(ca_id_str)
            for st in ta.get("subtrees", []):
                cp_bytes = encode_mtc_subtree_checkpoint(
                    ca_id_bytes,
                    int(st["logNumber"]),
                    int(st["start"]),
                    int(st["end"]),
                    b64url_decode(st["rootHash"]),
                )
                sig_bytes = b64url_decode(st["signature"])
                verified = any(
                    verify_hss_lms_signature(hpub, cp_bytes, sig_bytes)
                    for hpub in mds_hss_pubs
                )
                assert verified, f"MTC subtree checkpoint for caId={ca_id_str} failed HSS/LMS verification!"
                print(
                    f"[VERIFIED] MDS mtcTrustAnchors caId='{ca_id_str}' subtree checkpoint "
                    f"(alg={st['alg']}, sig={len(sig_bytes)} B) verified under MDS LMS trust anchor"
                )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate RFC 8554 / NIST SP 800-208 HSS/LMS Root CA, Pre-Published Intermediate CAs "
            "for FIDO MDS, and LMS-signed X.509 batch certificates for ML-DSA-44, ML-DSA-65, and ML-DSA-87."
        )
    )
    parser.add_argument(
        "--num-intermediates",
        type=int,
        default=4,
        help="Number of LMS_SHA256_M32_H5 Intermediate CAs to pre-publish in MDS (default: 4 = 128 batches).",
    )
    parser.add_argument(
        "--intermediate-index",
        type=int,
        default=0,
        help="Active LMS Intermediate CA index used to sign batch certificates (default: 0).",
    )
    parser.add_argument(
        "--enterprise-serial",
        default="123456",
        help='FIDO Enterprise serial number for crypto_data_enterprise/fidont_cert.pem (default: "123456").',
    )
    parser.add_argument(
        "--fw-version",
        type=int,
        default=None,
        help="Firmware version integer (default: read OPENSK_FIRMWARE_VERSION from src/env.rs).",
    )
    parser.add_argument(
        "--force-regen-ca",
        action="store_true",
        default=False,
        help="Force regeneration of the LMS Root CA and Intermediate CAs.",
    )
    parser.add_argument(
        "--no-update-mds",
        action="store_true",
        default=False,
        help="Do not update metadata/*.json with the LMS Root/Intermediate CAs.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        default=False,
        help="Only verify existing LMS Root, Intermediate, Batch certificates, and MDS checkpoints.",
    )
    args = parser.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if args.verify_only:
        verify_all_lms_artifacts(repo_root)
        return

    summary = generate_lms_hierarchy_and_batch_certs(
        repo_root=repo_root,
        num_intermediates=args.num_intermediates,
        active_intermediate_idx=args.intermediate_index,
        enterprise_serial=args.enterprise_serial,
        fw_version=args.fw_version,
        force_regen_ca=args.force_regen_ca,
        update_mds=not args.no_update_mds,
    )
    print(
        f"[OK] Generated LMS Root CA ({summary['rootCa']['derLengthBytes']} B DER) + "
        f"{len(summary['intermediates'])} Pre-Published LMS Intermediate CAs "
        f"({summary['intermediates'][0]['derLengthBytes']} B DER each)"
    )
    for dname, binfo in summary["batchCertificates"].items():
        print(
            f"     - {dname}/fidont_cert.pem ({binfo['subjectAlg']}, alg={binfo['coseAlg']}): "
            f"{binfo['derLengthBytes']} B DER (signed by Intermediate #{binfo['signedByIntermediateIndex']} leaf q={binfo['intermediateLeafQ']})"
        )
    verify_all_lms_artifacts(repo_root)


if __name__ == "__main__":
    main()
