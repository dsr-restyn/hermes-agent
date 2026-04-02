"""Integration tests: proxy server substitutes credentials in live HTTP traffic."""

import asyncio
import os
import pytest
from pathlib import Path

import aiohttp
import aiohttp.web

from cred_proxy.ca import LocalCA
from cred_proxy.server import CredProxy
from cred_proxy.store import CredStore

@pytest.mark.asyncio
async def test_http_proxy_substitutes_auth_header(tmp_path: Path) -> None:
    """HTTP request through proxy has Authorization header placeholder replaced."""
    store = CredStore(key_file=tmp_path / "k.key", store_file=tmp_path / "s.enc")
    store.set("mytoken", "real-secret-value")

    received: dict = {}

    async def mock_handler(request: aiohttp.web.Request) -> aiohttp.web.Response:
        received["authorization"] = request.headers.get("Authorization", "")
        return aiohttp.web.Response(text="ok")

    app = aiohttp.web.Application()
    app.router.add_get("/", mock_handler)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    # asyncio.Server.sockets is stable stdlib API (Python 3.7+)
    port = site._server.sockets[0].getsockname()[1]

    ca = LocalCA(ca_dir=tmp_path / "ca")
    sock_path = str(tmp_path / "proxy.sock")
    proxy = CredProxy(store, ca, sock_path)

    # Start only the asyncio server (not via proxy.start() which blocks forever)
    raw_server = await asyncio.start_unix_server(proxy._handle_client, path=sock_path)
    os.chmod(sock_path, 0o600)

    try:
        reader, writer = await asyncio.open_unix_connection(sock_path)

        target = f"http://127.0.0.1:{port}/"
        http_request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer hermes-proxy://mytoken\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(http_request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        assert b"200" in response, f"Expected 200 response, got: {response[:200]}"
        assert received.get("authorization") == "Bearer real-secret-value", (
            f"Expected substituted value, got: {received.get('authorization')!r}"
        )

    finally:
        raw_server.close()
        await raw_server.wait_closed()
        await runner.cleanup()


def test_no_public_get_api(tmp_path: Path) -> None:
    """CredStore has no public method to retrieve stored credential values.

    The agent process structurally cannot read back secrets — only _get()
    exists and it is intentionally private (name starts with underscore).
    """
    store = CredStore(key_file=tmp_path / "k.key", store_file=tmp_path / "s.enc")
    store.set("secret", "sensitive-value")

    public_methods = {
        m
        for m in dir(store)
        if not m.startswith("_") and callable(getattr(store, m))
    }
    assert public_methods == {"set", "list", "delete"}, (
        f"Unexpected public methods on CredStore: {public_methods - {'set', 'list', 'delete'}}"
    )
