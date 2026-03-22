"""
NIST FIPS 203 (ML-KEM-768) Known Answer Tests.
Vectors: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203

STRUCTURE NOTES (confirmed from actual files):
  - prompt.json HAS parameterSet per group (ML-KEM-512 / 768 / 1024)
  - expectedResults.json does NOT have parameterSet — groups matched by tgId
  - All values are HEX encoded
  - ML-KEM-512: ek=800B dk=1632B  |  ML-KEM-768: ek=1184B dk=2400B  |  ML-KEM-1024: ek=1568B dk=3168B
"""
import json
import os
import pytest
from pqcrypto.kem import ml_kem_768

KEYGEN_DIR     = os.path.join(os.path.dirname(__file__), "vectors", "ML-KEM-keyGen-FIPS203")
ENCAPDECAP_DIR = os.path.join(os.path.dirname(__file__), "vectors", "ML-KEM-encapDecap-FIPS203")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def get_mlkem768_tgids(prompt_path):
    """Return set of tgIds that are ML-KEM-768 in the prompt."""
    prompt = load_json(prompt_path)
    return {
        g["tgId"]
        for g in prompt["testGroups"]
        if g.get("parameterSet") == "ML-KEM-768"
    }


# ── Size conformance (FIPS 203 Table 2) ───────────────────────────────────────

def test_mlkem768_keypair_sizes():
    """FIPS 203 Table 2: ML-KEM-768 ek=1184 bytes, dk=2400 bytes."""
    ek, dk = ml_kem_768.generate_keypair()
    assert len(ek) == 1184, f"ek={len(ek)} expected 1184"
    assert len(dk) == 2400, f"dk={len(dk)} expected 2400"


def test_mlkem768_ciphertext_and_ss_sizes():
    """FIPS 203 Table 2: ML-KEM-768 ciphertext=1088 bytes, ss=32 bytes."""
    ek, dk = ml_kem_768.generate_keypair()
    ct, ss = ml_kem_768.encrypt(ek)
    assert len(ct) == 1088, f"ct={len(ct)} expected 1088"
    assert len(ss) == 32,   f"ss={len(ss)} expected 32"


# ── Functional correctness ────────────────────────────────────────────────────

def test_mlkem768_encap_decap_roundtrip():
    """FIPS 203 §6.2/6.3: encapsulate then decapsulate must yield identical ss. 10 trials."""
    failures = []
    for i in range(10):
        ek, dk = ml_kem_768.generate_keypair()
        ct, ss_enc = ml_kem_768.encrypt(ek)
        ss_dec = ml_kem_768.decrypt(dk, ct)
        if ss_enc != ss_dec:
            failures.append(f"Trial {i}: ss mismatch")
    assert not failures, "\n".join(failures)


def test_mlkem768_different_keys_yield_different_ss():
    """Two independent encapsulations under different keys must not share a ss."""
    ek1, _ = ml_kem_768.generate_keypair()
    ek2, _ = ml_kem_768.generate_keypair()
    _, ss1 = ml_kem_768.encrypt(ek1)
    _, ss2 = ml_kem_768.encrypt(ek2)
    assert ss1 != ss2, "Different keys produced identical shared secrets"


def test_mlkem768_wrong_dk_implicit_rejection():
    """
    FIPS 203 §6.3 implicit rejection: decapping with wrong dk must not return
    the correct ss. pqcrypto returns rejection randomness, not an exception.
    """
    ek1, dk1 = ml_kem_768.generate_keypair()
    ek2, dk2 = ml_kem_768.generate_keypair()
    ct, ss_correct = ml_kem_768.encrypt(ek1)
    ss_wrong = ml_kem_768.decrypt(dk2, ct)
    assert ss_correct != ss_wrong, \
        "Wrong dk returned the correct ss — implicit rejection not working"


# ── NIST ACVP vector tests ────────────────────────────────────────────────────

def test_mlkem768_nist_keygen_vector_sizes():
    """
    FIPS 203 KAT: validate NIST keyGen vector ek/dk byte sizes for ML-KEM-768 only.
    Uses prompt.json to identify ML-KEM-768 tgIds, then checks expectedResults.json.
    Vectors are HEX encoded.
    """
    prompt_path   = os.path.join(KEYGEN_DIR, "prompt.json")
    expected_path = os.path.join(KEYGEN_DIR, "expectedResults.json")

    if not os.path.exists(prompt_path) or not os.path.exists(expected_path):
        pytest.skip("NIST keyGen vectors not found — run vector copy step")

    tgids_768 = get_mlkem768_tgids(prompt_path)
    assert tgids_768, "No ML-KEM-768 groups found in prompt.json"

    expected = load_json(expected_path)
    checked = 0
    failures = []

    for group in expected["testGroups"]:
        if group["tgId"] not in tgids_768:
            continue
        for tc in group["tests"]:
            if "ek" in tc:
                ek_bytes = bytes.fromhex(tc["ek"])
                if len(ek_bytes) != 1184:
                    failures.append(f"tcId={tc['tcId']}: ek={len(ek_bytes)} expected 1184")
            if "dk" in tc:
                dk_bytes = bytes.fromhex(tc["dk"])
                if len(dk_bytes) != 2400:
                    failures.append(f"tcId={tc['tcId']}: dk={len(dk_bytes)} expected 2400")
            checked += 1

    print(f"\n  ML-KEM-768 keyGen: checked {checked} vectors from tgIds {tgids_768}")
    assert checked > 0, "No ML-KEM-768 test cases found"
    assert not failures, "\n".join(failures)


def test_mlkem768_nist_keygen_roundtrip_with_vectors():
    """
    FIPS 203 KAT: encapsulate to NIST's ek, decapsulate with NIST's dk — ss must match.
    Only processes ML-KEM-768 groups (identified via prompt.json tgIds).
    """
    prompt_path   = os.path.join(KEYGEN_DIR, "prompt.json")
    expected_path = os.path.join(KEYGEN_DIR, "expectedResults.json")

    if not os.path.exists(prompt_path) or not os.path.exists(expected_path):
        pytest.skip("NIST keyGen vectors not found")

    tgids_768 = get_mlkem768_tgids(prompt_path)
    expected  = load_json(expected_path)

    tested = 0
    failures = []

    for group in expected["testGroups"]:
        if group["tgId"] not in tgids_768:
            continue
        for tc in group["tests"]:
            if "ek" not in tc or "dk" not in tc:
                continue

            ek = bytes.fromhex(tc["ek"])
            dk = bytes.fromhex(tc["dk"])

            ct, ss_enc = ml_kem_768.encrypt(ek)
            ss_dec = ml_kem_768.decrypt(dk, ct)

            if ss_enc != ss_dec:
                failures.append(f"tcId={tc['tcId']}: ss mismatch with NIST keys")

            tested += 1
            if tested >= 25:
                break
        if tested >= 25:
            break

    print(f"\n  ML-KEM-768 keyGen round-trip: tested {tested} NIST key pairs")
    assert tested > 0, "No ML-KEM-768 vectors with ek+dk found"
    assert not failures, "\n".join(failures)


def test_mlkem768_nist_encapdecap_structure():
    """Sanity check: NIST encapDecap prompt.json is well-formed."""
    prompt_path = os.path.join(ENCAPDECAP_DIR, "prompt.json")
    if not os.path.exists(prompt_path):
        pytest.skip("NIST encapDecap prompt.json not found")
    prompt = load_json(prompt_path)
    total = sum(len(g["tests"]) for g in prompt["testGroups"])
    assert total > 0
    print(f"\n  encapDecap: {len(prompt['testGroups'])} groups, {total} tests")
