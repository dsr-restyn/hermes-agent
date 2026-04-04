"""Credential store — in-memory for Phase 1.

All secrets live in a plain dict in the proxy process's heap.  They do not
persist across proxy restarts — users must re-add credentials after each
``hermes cred-proxy start``.

Phase 3 will add AES-256-GCM encrypted persistence (unlocked by a master
passphrase at daemon start, never stored on disk).

No external dependencies — stdlib only.

Public API: set(), list(), delete()
Internal:   _get()  — used only by the substitutor, never exposed to callers.
"""


class CredStore:
    """In-memory credential store.

    Thread-safety note: the proxy runs as a single-threaded asyncio event loop,
    so no locking is required.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set(self, name: str, value: str) -> None:
        """Store a credential under *name*."""
        self._store[name] = value

    def list(self) -> list[str]:
        """Return sorted list of stored credential names (no values)."""
        return sorted(self._store.keys())

    def delete(self, name: str) -> None:
        """Remove credential *name* from the store.

        Raises KeyError if the name does not exist.
        """
        if name not in self._store:
            raise KeyError(f"Credential {name!r} not found")
        del self._store[name]

    # ------------------------------------------------------------------
    # Internal-only access (used by substitutor — NOT part of public API)
    # ------------------------------------------------------------------

    def _get(self, name: str) -> str:
        """Return the value for *name*.

        Intentionally private: agent processes must not be able to call
        this through any public interface.  Raises KeyError if not found.
        """
        if name not in self._store:
            raise KeyError(f"Credential {name!r} not found")
        return self._store[name]
