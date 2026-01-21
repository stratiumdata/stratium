from __future__ import annotations

import base64
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from stratium_sdk import crypto


class CryptoTests(unittest.TestCase):
    def test_dek_round_trip(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        dek = crypto.generate_dek()

        ciphertext = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        decrypted = crypto.decrypt_dek(ciphertext, private_key)
        self.assertEqual(dek, decrypted)

    def test_policy_binding_is_deterministic(self) -> None:
        dek = crypto.generate_dek()
        policy_base64 = base64.b64encode(b'{"foo":"bar"}').decode("ascii")
        binding = crypto.calculate_policy_binding(dek, policy_base64)
        self.assertTrue(crypto.verify_policy_binding(dek, policy_base64, base64.b64encode(binding).decode("ascii")))


if __name__ == "__main__":
    unittest.main()
