"""Tests for cred_proxy.store (encrypted credential store)."""

import pytest
from pathlib import Path

from cred_proxy.store import CredStore


@pytest.fixture
def store(tmp_path: Path) -> CredStore:
    return CredStore(
        key_file=tmp_path / "test.key",
        store_file=tmp_path / "test.enc",
    )


def test_set_and_list_shows_name(store: CredStore) -> None:
    store.set("mytoken", "secret-value")
    assert "mytoken" in store.list()


def test_list_empty_by_default(store: CredStore) -> None:
    assert store.list() == []


def test_list_multiple_names_sorted(store: CredStore) -> None:
    store.set("zebra", "v1")
    store.set("alpha", "v2")
    store.set("middle", "v3")
    assert store.list() == ["alpha", "middle", "zebra"]


def test_get_returns_correct_value_after_reload(tmp_path: Path) -> None:
    key_file = tmp_path / "k.key"
    store_file = tmp_path / "s.enc"

    s1 = CredStore(key_file=key_file, store_file=store_file)
    s1.set("api_key", "top-secret-123")

    # Re-open with same files (simulates process restart)
    s2 = CredStore(key_file=key_file, store_file=store_file)
    assert s2._get("api_key") == "top-secret-123"


def test_store_file_is_encrypted(store: CredStore, tmp_path: Path) -> None:
    plaintext_value = "my-super-secret-password"
    store.set("pw", plaintext_value)

    raw_bytes = (tmp_path / "test.enc").read_bytes()
    assert plaintext_value.encode() not in raw_bytes, (
        "Plaintext value must not appear in the raw store file"
    )


def test_delete_removes_name(store: CredStore) -> None:
    store.set("tok", "val")
    store.delete("tok")
    assert "tok" not in store.list()


def test_delete_raises_key_error_for_missing(store: CredStore) -> None:
    with pytest.raises(KeyError):
        store.delete("nonexistent")


def test_get_raises_key_error_for_missing(store: CredStore) -> None:
    with pytest.raises(KeyError):
        store._get("nonexistent")


def test_overwrite_updates_value(store: CredStore) -> None:
    store.set("key", "old-value")
    store.set("key", "new-value")
    assert store._get("key") == "new-value"
    assert store.list().count("key") == 1  # no duplicates
