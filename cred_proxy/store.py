"""Encrypted credential store using AES-256-GCM.

Key file:   ~/.hermes/state/cred-proxy.key  (chmod 600, 32 random bytes)
Store file: ~/.hermes/state/cred-store.enc  (JSON, each value AES-256-GCM encrypted)

Public API: set(), list(), delete()
Internal:   _get()  — used only by the substitutor, never exposed to callers.
"""

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DEFAULT_STATE_DIR = Path.home() / ".hermes" / "state"
_DEFAULT_KEY_FILE = _DEFAULT_STATE_DIR / "cred-proxy.key"
_DEFAULT_STORE_FILE = _DEFAULT_STATE_DIR / "cred-store.enc"


class CredStore:
    def __init__(
        self,
        key_file: Path = _DEFAULT_KEY_FILE,
        store_file: Path = _DEFAULT_STORE_FILE,
    ):
        self._key_file = Path(key_file)
        self._store_file = Path(store_file)
        self._key = self._load_or_create_key()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_or_create_key(self) -> bytes:
        self._key_file.parent.mkdir(parents=True, exist_ok=True)
        if self._key_file.exists():
            data = self._key_file.read_bytes()
            if len(data) == 32:
                return data
        key = os.urandom(32)
        self._key_file.write_bytes(key)
        self._key_file.chmod(0o600)
        return key

    def _load_store(self) -> dict:
        if not self._store_file.exists():
            return {}
        try:
            return json.loads(self._store_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_store(self, data: dict) -> None:
        self._store_file.parent.mkdir(parents=True, exist_ok=True)
        self._store_file.write_text(json.dumps(data))
        os.chmod(self._store_file, 0o600)

    def _encrypt(self, value: str) -> dict:
        aesgcm = AESGCM(self._key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
        }

    def _decrypt(self, entry: dict) -> str:
        aesgcm = AESGCM(self._key)
        nonce = base64.b64decode(entry["nonce"])
        ct = base64.b64decode(entry["ct"])
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set(self, name: str, value: str) -> None:
        """Store an encrypted credential under *name*."""
        store = self._load_store()
        store[name] = self._encrypt(value)
        self._save_store(store)

    def list(self) -> list[str]:
        """Return sorted list of stored credential names (no values)."""
        return sorted(self._load_store().keys())

    def delete(self, name: str) -> None:
        """Remove credential *name* from the store.

        Raises KeyError if the name does not exist.
        """
        store = self._load_store()
        if name not in store:
            raise KeyError(f"Credential {name!r} not found")
        del store[name]
        self._save_store(store)

    # ------------------------------------------------------------------
    # Internal-only access (used by substitutor — NOT part of public API)
    # ------------------------------------------------------------------

    def _get(self, name: str) -> str:
        """Decrypt and return the value for *name*.

        Intentionally private: agent processes must not be able to call
        this through any public interface.  Raises KeyError if not found.
        """
        store = self._load_store()
        if name not in store:
            raise KeyError(f"Credential {name!r} not found")
        return self._decrypt(store[name])
