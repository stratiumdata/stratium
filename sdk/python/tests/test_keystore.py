from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from stratium_sdk.keystore import FileKeyStore, KeyMetadata, StoredKeyPair


class FileKeyStoreTests(unittest.TestCase):
    def test_save_and_load_key_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = FileKeyStore(Path(temp_dir))
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            metadata = KeyMetadata(
                key_id="test-key",
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            store.save_key_pair(StoredKeyPair(metadata=metadata, public_key=key.public_key(), private_key=key))

            loaded = store.get_latest_key()
            self.assertIsNotNone(loaded)
            assert loaded
            self.assertEqual(loaded.metadata.key_id, "test-key")
            self.assertFalse(loaded.metadata.expired)


if __name__ == "__main__":
    unittest.main()
