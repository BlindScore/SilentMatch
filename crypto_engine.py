"""
crypto_engine.py
Core mathematical operations for the OPRF protocol.
"""
import hashlib
from config import PRIME_MODULUS

class OPRFMath:
    @staticmethod
    def map_string_to_group(text: str) -> int:
        """
        Deterministically maps a string (email) to a large integer.
        Step 1 of the protocol.
        """
        clean_text = text.strip().lower().replace(" ", "")
        h = hashlib.sha256(clean_text.encode()).hexdigest()
        return int(h, 16)

    @staticmethod
    def mod_pow(base: int, exponent: int) -> int:
        """
        Computes (base ^ exponent) % PRIME_MODULUS efficiently.
        Used for Blinding, Signing, and Unblinding.
        """
        return pow(base, exponent, PRIME_MODULUS)

    @staticmethod
    def mod_inverse(value: int) -> int:
        """
        Computes the modular multiplicative inverse.
        Essential for the 'Unblinding' step.
        """
        return pow(value, -1, PRIME_MODULUS - 1)