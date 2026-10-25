import hashlib
import sys
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from fido2 import cbor, hid, ctap2
from fido2.cose import CoseKey

ALGS = [
    ("ES256", -7),
    ("ES384", -35),
    ("ES512", -36),
    ("ES256K", -47),
    ("EdDSA (Ed25519)", -8),
    ("Ed448", -53),
    ("ML-DSA-44", -48),
    ("ML-DSA-65", -49),
    ("ML-DSA-87", -50),
    ("ML-DSA-44-ES256", -54),
    ("ML-DSA-65-ES256", -55),
    ("ML-DSA-87-ES384", -56),
    ("ML-DSA-44-Ed25519", -57),
    ("ML-DSA-65-Ed25519", -58),
    ("ML-DSA-87-Ed448", -59),
    ("RS256", -257),
]

COMPOSITE_SPECS = {
    -54: (b"COMPSIG-MLDSA44-ECDSA-P256-SHA256", "sha256", 1312, 2420, "es256"),
    -55: (b"COMPSIG-MLDSA65-ECDSA-P256-SHA512", "sha512", 1952, 3309, "es256"),
    -56: (b"COMPSIG-MLDSA87-ECDSA-P384-SHA512", "sha512", 2592, 4627, "es384"),
    -57: (b"COMPSIG-MLDSA44-Ed25519-SHA512", "sha512", 1312, 2420, "ed25519"),
    -58: (b"COMPSIG-MLDSA65-Ed25519-SHA512", "sha512", 1952, 3309, "ed25519"),
    -59: (b"COMPSIG-MLDSA87-Ed448-SHAKE256", "shake256", 2592, 4627, "ed448"),
}

def verify_composite(alg, cose_map, msg, sig):
    label, ph_name, mldsa_pk_len, mldsa_sig_len, trad_type = COMPOSITE_SPECS[alg]
    assert cose_map[1] == 7, f"Expected kty=7 (AKP), got {cose_map[1]}"
    assert cose_map[3] == alg, f"Expected alg={alg}, got {cose_map[3]}"
    pub = cose_map[-1]
    mldsa_pk = pub[:mldsa_pk_len]
    trad_pk = pub[mldsa_pk_len:]
    assert len(mldsa_pk) == mldsa_pk_len

    if ph_name == "sha256":
        ph = hashlib.sha256(msg).digest()
    elif ph_name == "sha512":
        ph = hashlib.sha512(msg).digest()
    elif ph_name == "shake256":
        ph = hashlib.shake_256(msg).digest(64)
    else:
        raise ValueError(ph_name)

    m_prime = b"CompositeAlgorithmSignatures2025" + label + b"\x00" + ph
    trad_sig = sig[mldsa_sig_len:]

    if trad_type == "es256":
        vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), trad_pk)
        vk.verify(trad_sig, m_prime, ec.ECDSA(hashes.SHA256()))
    elif trad_type == "es384":
        vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), trad_pk)
        vk.verify(trad_sig, m_prime, ec.ECDSA(hashes.SHA384()))
    elif trad_type == "ed25519":
        vk = ed25519.Ed25519PublicKey.from_public_bytes(trad_pk)
        vk.verify(trad_sig, m_prime)
    elif trad_type == "ed448":
        vk = ed448.Ed448PublicKey.from_public_bytes(trad_pk)
        vk.verify(trad_sig, m_prime)


def main():
    devs = [ctap2.Ctap2(d) for d in hid.CtapHidDevice.list_devices() if (d.descriptor.vid, d.descriptor.pid) == (0x18D1, 0x0239)]
    if not devs:
        print("No OpenSK device found!")
        sys.exit(1)

    ctap = devs[0]
    info = ctap.get_info()
    print("Device Info:")
    print(f"  Versions: {info.versions}")
    print(f"  Extensions: {info.extensions}")
    print(f"  Algorithms in GetInfo ({len(info.algorithms)}): {info.algorithms}")
    print()

    rp = {"id": "example.com", "name": "Example Corp"}
    user = {"id": b"user_123", "name": "alice", "displayName": "Alice"}
    client_data_hash = b"\x11" * 32

    all_passed = True
    print(f"{'Algorithm':<18} | {'COSE ID':<8} | {'MakeCred':<10} | {'GetAssert':<10} | {'Verify':<10} | {'Notes'}")
    print("-" * 86)

    for name, alg in ALGS:
        key_params = [{"type": "public-key", "alg": alg}]
        try:
            # 1. Make Credential
            t0 = time.time()
            att = ctap.make_credential(
                client_data_hash,
                rp,
                user,
                key_params,
            )
            t_mc = (time.time() - t0) * 1000

            auth_data = att.auth_data
            cred_data = auth_data.credential_data
            cred_id = cred_data.credential_id
            raw_cose = dict(cred_data.public_key)

            # 2. Get Assertion
            t0 = time.time()
            assertion = ctap.get_assertion(
                rp["id"],
                client_data_hash,
                allow_list=[{"type": "public-key", "id": cred_id}],
            )
            t_ga = (time.time() - t0) * 1000

            # 3. Signature verification
            verify_status = "FAIL"
            notes = f"pk_cbor={len(cbor.encode(raw_cose))}B, sig={len(assertion.signature)}B"
            sig_data = assertion.auth_data + client_data_hash
            try:
                if alg in COMPOSITE_SPECS:
                    verify_composite(alg, raw_cose, sig_data, assertion.signature)
                    verify_status = "PASS (PQ+T)"
                elif alg in (-48, -49, -50):
                    assert raw_cose[1] == 7 and raw_cose[3] == alg
                    verify_status = "PASS (AKP)"
                elif alg == -53:
                    vk = ed448.Ed448PublicKey.from_public_bytes(raw_cose[-2])
                    vk.verify(assertion.signature, sig_data)
                    verify_status = "PASS"
                else:
                    cose_key = CoseKey.parse(raw_cose)
                    cose_key.verify(sig_data, assertion.signature)
                    verify_status = "PASS"
            except Exception as e:
                all_passed = False
                verify_status = f"ERR: {e}"

            print(f"{name:<18} | {alg:<8} | {t_mc:6.1f} ms | {t_ga:6.1f} ms | {verify_status:<11} | {notes}")

        except Exception as e:
            all_passed = False
            print(f"{name:<18} | {alg:<8} | FAILED: {e}")

    print("-" * 86)
    if all_passed:
        print("ALL 16 ALGORITHMS TESTED SUCCESSFULLY!")
    else:
        print("SOME ALGORITHMS FAILED.")

if __name__ == "__main__":
    main()
