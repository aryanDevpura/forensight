"""
Focused tests for the AES Confusion & Diffusion demonstration endpoint.

POST /api/evidence/crypto-lab/aes-confusion-diffusion
"""

import pytest
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()


# --------------------------------------------------------------------------
# 1. Default parameters (empty body)
# --------------------------------------------------------------------------

def test_aes_default_params_returns_200():
    """POST with empty body should use defaults and return 200."""
    resp = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["cipher_algorithm"] == "AES-128 (Single Block 128-bit Permutation)"
    assert data["block_size_bits"] == 128


def test_aes_default_confusion_experiment():
    """Confusion experiment with defaults should flip key bit 0."""
    resp = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json={})
    data = resp.json()
    confusion = data["confusion_experiment"]
    assert confusion["experiment_name"] == "Confusion (Key Sensitivity)"
    assert confusion["total_bits"] == 128
    assert confusion["flipped_bit_index"] == 0
    assert confusion["changed_bits"] > 0
    # Avalanche: expect roughly 30-70% changed bits (not exact 50%)
    assert 20.0 < confusion["changed_percentage"] < 80.0
    # Ciphertexts should be 32-char hex strings (16 bytes)
    assert len(confusion["ciphertext_a_hex"]) == 32
    assert len(confusion["ciphertext_b_hex"]) == 32
    assert confusion["ciphertext_a_hex"] != confusion["ciphertext_b_hex"]


def test_aes_default_diffusion_experiment():
    """Diffusion experiment with defaults should flip plaintext bit 0."""
    resp = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json={})
    data = resp.json()
    diffusion = data["diffusion_experiment"]
    assert diffusion["experiment_name"] == "Diffusion (Plaintext Sensitivity)"
    assert diffusion["total_bits"] == 128
    assert diffusion["flipped_bit_index"] == 0
    assert diffusion["changed_bits"] > 0
    assert 20.0 < diffusion["changed_percentage"] < 80.0
    assert len(diffusion["ciphertext_a_hex"]) == 32
    assert len(diffusion["ciphertext_b_hex"]) == 32


def test_aes_default_educational_fields():
    """Response should contain educational summary and security disclaimer."""
    resp = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json={})
    data = resp.json()
    assert "avalanche" in data["educational_summary"].lower()
    assert "50%" in data["security_disclaimer"] or "50 %" in data["security_disclaimer"]


# --------------------------------------------------------------------------
# 2. Custom parameters
# --------------------------------------------------------------------------

def test_aes_custom_bit_flip_indices():
    """Flipping different bit indices should work and produce different results."""
    resp_bit0 = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_bit_to_flip": 0, "plaintext_bit_to_flip": 0},
    )
    resp_bit7 = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_bit_to_flip": 7, "plaintext_bit_to_flip": 7},
    )
    assert resp_bit0.status_code == 200
    assert resp_bit7.status_code == 200
    data0 = resp_bit0.json()
    data7 = resp_bit7.json()
    # Different bit flips should (almost certainly) give different ciphertexts
    assert (
        data0["confusion_experiment"]["ciphertext_b_hex"]
        != data7["confusion_experiment"]["ciphertext_b_hex"]
    )


def test_aes_custom_plaintext_and_key():
    """User-supplied 16-byte hex values should be accepted."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={
            "plaintext_hex": "00112233445566778899aabbccddeeff",
            "key_hex": "000102030405060708090a0b0c0d0e0f",
            "key_bit_to_flip": 64,
            "plaintext_bit_to_flip": 64,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["confusion_experiment"]["flipped_bit_index"] == 64
    assert data["diffusion_experiment"]["flipped_bit_index"] == 64


def test_aes_deterministic_results():
    """Same inputs should always produce exactly the same ciphertexts (ECB is deterministic)."""
    body = {"plaintext_hex": "aabbccdd11223344aabbccdd11223344", "key_hex": "11223344556677889900aabbccddeeff"}
    resp1 = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json=body)
    resp2 = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json=body)
    d1 = resp1.json()
    d2 = resp2.json()
    assert d1["confusion_experiment"]["ciphertext_a_hex"] == d2["confusion_experiment"]["ciphertext_a_hex"]
    assert d1["confusion_experiment"]["ciphertext_b_hex"] == d2["confusion_experiment"]["ciphertext_b_hex"]
    assert d1["diffusion_experiment"]["ciphertext_a_hex"] == d2["diffusion_experiment"]["ciphertext_a_hex"]
    assert d1["diffusion_experiment"]["ciphertext_b_hex"] == d2["diffusion_experiment"]["ciphertext_b_hex"]


# --------------------------------------------------------------------------
# 3. Bit-difference binary mask
# --------------------------------------------------------------------------

def test_aes_bit_differences_binary_mask_length():
    """Binary mask should always be exactly 128 characters of '0' and '1'."""
    resp = client.post("/api/evidence/crypto-lab/aes-confusion-diffusion", json={})
    data = resp.json()
    for trial_key in ("confusion_experiment", "diffusion_experiment"):
        mask = data[trial_key]["bit_differences_binary"]
        assert len(mask) == 128
        assert all(c in ("0", "1") for c in mask)
        # Number of '1's should match changed_bits
        assert mask.count("1") == data[trial_key]["changed_bits"]


# --------------------------------------------------------------------------
# 4. Error handling
# --------------------------------------------------------------------------

def test_aes_invalid_plaintext_hex_length():
    """plaintext_hex that isn't 32 hex chars (16 bytes) should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"plaintext_hex": "aabb"},
    )
    assert resp.status_code == 400
    assert "16 bytes" in resp.json()["detail"]


def test_aes_invalid_key_hex_length():
    """key_hex that isn't 32 hex chars (16 bytes) should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_hex": "ff" * 32},  # 64 hex chars = 32 bytes, too long
    )
    assert resp.status_code == 400
    assert "16 bytes" in resp.json()["detail"]


def test_aes_invalid_key_hex_chars():
    """Non-hex characters in key_hex should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
    )
    assert resp.status_code == 400


def test_aes_bit_flip_out_of_range():
    """key_bit_to_flip >= 128 should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_bit_to_flip": 128},
    )
    assert resp.status_code == 400
    assert "127" in resp.json()["detail"]


def test_aes_plaintext_bit_flip_out_of_range():
    """plaintext_bit_to_flip >= 128 should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"plaintext_bit_to_flip": 200},
    )
    assert resp.status_code == 400
    assert "127" in resp.json()["detail"]


def test_aes_negative_bit_flip():
    """Negative bit flip index should return 400."""
    resp = client.post(
        "/api/evidence/crypto-lab/aes-confusion-diffusion",
        json={"key_bit_to_flip": -1},
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# 5. GET endpoint removed
# --------------------------------------------------------------------------

def test_aes_get_endpoint_not_available():
    """GET /crypto-lab/aes-confusion-diffusion should return 405 (only POST is allowed)."""
    resp = client.get("/api/evidence/crypto-lab/aes-confusion-diffusion")
    assert resp.status_code == 405

