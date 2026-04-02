"""Tests for specific bug fixes in the credential proxy."""

import asyncio
import os
import subprocess

import aiohttp
import aiohttp.web
import pytest
from pathlib import Path

from cred_proxy.ca import LocalCA
from cred_proxy.server import CredProxy
from cred_proxy.store import CredStore


# ---------------------------------------------------------------------------
# Fix 1: Content-Length is correct after body substitution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_content_length_updated_after_body_substitution(tmp_path: Path) -> None:
    """Proxy updates Content-Length to match body after placeholder substitution."""
    store = CredStore(key_file=tmp_path / "k.key", store_file=tmp_path / "s.enc")
    # placeholder "hermes-proxy://tok" (18 chars) → "x" (1 char): body shrinks
    store.set("tok", "x")

    received: dict = {}

    async def mock_handler(request: aiohttp.web.Request) -> aiohttp.web.Response:
        received["content_length"] = request.headers.get("Content-Length", "")
        received["body"] = await request.text()
        return aiohttp.web.Response(text="ok")

    app = aiohttp.web.Application()
    app.router.add_post("/", mock_handler)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    ca = LocalCA(ca_dir=tmp_path / "ca")
    sock_path = str(tmp_path / "proxy.sock")
    proxy = CredProxy(store, ca, sock_path)

    raw_server = await asyncio.start_unix_server(proxy._handle_client, path=sock_path)
    os.chmod(sock_path, 0o600)

    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)

        original_body = "secret=hermes-proxy://tok"
        target = f"http://127.0.0.1:{port}/"
        http_request = (
            f"POST {target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(original_body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{original_body}"
        )
        writer.write(http_request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        assert b"200" in response, f"Expected 200, got: {response[:200]}"
        expected_body = "secret=x"
        assert received.get("body") == expected_body, (
            f"Expected substituted body {expected_body!r}, got {received.get('body')!r}"
        )
        assert received.get("content_length") == str(len(expected_body)), (
            f"Expected Content-Length {len(expected_body)}, "
            f"got {received.get('content_length')!r}"
        )
    finally:
        raw_server.close()
        await raw_server.wait_closed()
        await runner.cleanup()


# ---------------------------------------------------------------------------
# Fix 5: Store file is chmod 600 after creation
# ---------------------------------------------------------------------------

def test_store_file_chmod_600_after_write(tmp_path: Path) -> None:
    """Store file has mode 0o600 after set() writes it."""
    store = CredStore(
        key_file=tmp_path / "test.key",
        store_file=tmp_path / "test.enc",
    )
    store.set("mykey", "myvalue")
    stat = (tmp_path / "test.enc").stat()
    assert stat.st_mode & 0o777 == 0o600, (
        f"Expected store file mode 0o600, got {oct(stat.st_mode & 0o777)}"
    )


def test_store_file_chmod_600_after_delete(tmp_path: Path) -> None:
    """Store file retains mode 0o600 after delete() rewrites it."""
    store = CredStore(
        key_file=tmp_path / "test.key",
        store_file=tmp_path / "test.enc",
    )
    store.set("a", "1")
    store.set("b", "2")
    store.delete("a")
    stat = (tmp_path / "test.enc").stat()
    assert stat.st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Fix 6: is_running() returns False and cleans up stale PID file
# ---------------------------------------------------------------------------

def test_is_running_cleans_up_stale_pid_and_port_files(tmp_path, monkeypatch):
    """is_running() returns False and removes stale PID + port files."""
    import cred_proxy.daemon as daemon_module

    pid_file = tmp_path / "cred-proxy.pid"
    port_file = tmp_path / "cred-proxy.port"

    monkeypatch.setattr(daemon_module, "_PID_FILE", pid_file)
    monkeypatch.setattr(daemon_module, "_PORT_FILE", port_file)

    # Find a PID that definitely does not exist on this system
    dead_pid = 999999
    try:
        os.kill(dead_pid, 0)
        pytest.skip("PID 999999 unexpectedly exists on this system")
    except ProcessLookupError:
        pass

    pid_file.write_text(str(dead_pid))
    port_file.write_text("12345")

    assert daemon_module.is_running() is False
    assert not pid_file.exists(), "Stale PID file was not removed"
    assert not port_file.exists(), "Stale port file was not removed"
