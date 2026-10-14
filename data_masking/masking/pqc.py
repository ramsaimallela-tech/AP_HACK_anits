"""Post-Quantum Cryptography (PQC) module.

Implements NIST FIPS 203 (ML-KEM-768 / CRYSTALS-Kyber) for post-quantum key encapsulation
and NIST FIPS 204 (ML-DSA-65 / CRYSTALS-Dilithium) for post-quantum digital signatures.
Provides envelope encryption and tamper-evident digital signatures.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768


KEYS_DIR = "keys"


class PQCManager:
    """Manages post-quantum keypairs, envelope encryption, and signing."""

    def __init__(self, keys_dir: str = KEYS_DIR):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)
        self.kem_pk: bytes | None = None
        self.kem_sk: bytes | None = None
        self.dsa_pk: bytes | None = None
        self.dsa_sk: bytes | None = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self) -> None:
        kem_pk_file = os.path.join(self.keys_dir, "kem_768_pk.bin")
        kem_sk_file = os.path.join(self.keys_dir, "kem_768_sk.bin")
        dsa_pk_file = os.path.join(self.keys_dir, "dsa_65_pk.bin")
        dsa_sk_file = os.path.join(self.keys_dir, "dsa_65_sk.bin")

        if os.path.exists(kem_pk_file) and os.path.exists(kem_sk_file):
            with open(kem_pk_file, "rb") as f:
                self.kem_pk = f.read()
            with open(kem_sk_file, "rb") as f:
                self.kem_sk = f.read()
        else:
            self.kem_pk, self.kem_sk = ML_KEM_768.keygen()
            with open(kem_pk_file, "wb") as f:
                f.write(self.kem_pk)
            with open(kem_sk_file, "wb") as f:
                f.write(self.kem_sk)

        if os.path.exists(dsa_pk_file) and os.path.exists(dsa_sk_file):
            with open(dsa_pk_file, "rb") as f:
                self.dsa_pk = f.read()
            with open(dsa_sk_file, "rb") as f:
                self.dsa_sk = f.read()
        else:
            self.dsa_pk, self.dsa_sk = ML_DSA_65.keygen()
            with open(dsa_pk_file, "wb") as f:
                f.write(self.dsa_pk)
            with open(dsa_sk_file, "wb") as f:
                f.write(self.dsa_sk)

    def get_public_keys_info(self) -> dict[str, Any]:
        return {
            "kem_algorithm": "ML-KEM-768 (NIST FIPS 203)",
            "kem_pk_fingerprint": hashlib.sha256(self.kem_pk).hexdigest()[:16],
            "kem_pk_size_bytes": len(self.kem_pk) if self.kem_pk else 0,
            "dsa_algorithm": "ML-DSA-65 (NIST FIPS 204)",
            "dsa_pk_fingerprint": hashlib.sha256(self.dsa_pk).hexdigest()[:16],
            "dsa_pk_size_bytes": len(self.dsa_pk) if self.dsa_pk else 0,
        }

    # ---- ML-KEM-768 Envelope Encryption -----------------------------------
    def envelope_encrypt(self, plaintext: bytes | str) -> dict[str, str]:
        """Encapsulates a shared key using ML-KEM-768, derives an AES-256 key,

        and encrypts plaintext with AES-256-GCM.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # 1. ML-KEM-768 Encapsulation
        shared_secret, kem_ciphertext = ML_KEM_768.encaps(self.kem_pk)

        # 2. Derive AES-256 key via HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"smartmask-quantum-pqc",
            info=b"pqc-envelope-encryption",
        )
        aes_key = hkdf.derive(shared_secret)

        # 3. Encrypt with AES-GCM (12-byte random nonce)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "algorithm": "ML-KEM-768 + AES-256-GCM",
            "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def envelope_decrypt(self, envelope: dict[str, str]) -> str:
        """Decapsulates shared key using ML-KEM-768 and decrypts ciphertext."""
        kem_ciphertext = base64.b64decode(envelope["kem_ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        # 1. ML-KEM-768 Decapsulation
        shared_secret = ML_KEM_768.decaps(self.kem_sk, kem_ciphertext)

        # 2. Derive AES-256 key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"smartmask-quantum-pqc",
            info=b"pqc-envelope-encryption",
        )
        aes_key = hkdf.derive(shared_secret)

        # 3. Decrypt AES-GCM
        aesgcm = AESGCM(aes_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")

    # ---- ML-DSA-65 Post-Quantum Signing -----------------------------------
    def sign(self, message: bytes | str) -> dict[str, str]:
        """Signs a message using ML-DSA-65."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        sig = ML_DSA_65.sign(self.dsa_sk, message)
        return {
            "sig_alg": "ML-DSA-65 (FIPS 204)",
            "signature": base64.b64encode(sig).decode("utf-8"),
            "key_id": hashlib.sha256(self.dsa_pk).hexdigest()[:16],
        }

    def verify(self, message: bytes | str, signature_b64: str) -> bool:
        """Verifies a signature using ML-DSA-65."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        try:
            sig = base64.b64decode(signature_b64)
            return ML_DSA_65.verify(self.dsa_pk, message, sig)
        except Exception:
            return False


# Singleton instance
_pqc_instance: PQCManager | None = None


def get_pqc_manager() -> PQCManager:
    global _pqc_instance
    if _pqc_instance is None:
        _pqc_instance = PQCManager()
    return _pqc_instance
