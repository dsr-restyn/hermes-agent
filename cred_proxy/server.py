"""asyncio HTTP/HTTPS MITM proxy server on a Unix domain socket.

HTTP flow:
  Client ──► proxy (parse + substitute headers/body) ──► real server
  Client ◄── proxy (forward response as-is)          ◄── real server

HTTPS CONNECT flow:
  Client ──► CONNECT hostname:port ──► proxy
  Client ◄── 200 Connection Established ◄── proxy
  (TLS handshake: client trusts proxy's per-hostname cert signed by local CA)
  Client ──► decrypted HTTP req ──► proxy (substitute) ──► real server (TLS)
  Client ◄── response ◄── proxy ◄── real server
"""

import asyncio
import logging
import os
import re
import socket
import ssl
import tempfile

from .ca import LocalCA
from .store import CredStore
from .substitutor import substitute

logger = logging.getLogger(__name__)

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_BODY_READ_LIMIT = 16 * 1024 * 1024  # 16 MiB


class CredProxy:
    def __init__(self, store: CredStore, ca: LocalCA, sock_path: str):
        self.store = store
        self.ca = ca
        self.sock_path = sock_path

    async def start(self, on_started=None) -> None:
        """Start serving on the Unix socket and a localhost TCP port.

        *on_started* is an optional callable invoked with the chosen TCP port
        after both servers are bound and listening.  Use it to write PID/port
        files so callers only see the daemon as ready once it is truly bound.
        """
        if os.path.exists(self.sock_path):
            os.unlink(self.sock_path)
        unix_server = await asyncio.start_unix_server(
            self._handle_client, path=self.sock_path
        )
        os.chmod(self.sock_path, 0o600)

        tcp_server = await asyncio.start_server(
            self._handle_client, host="127.0.0.1", port=0
        )
        tcp_port = tcp_server.sockets[0].getsockname()[1]

        logger.info(
            "Credential proxy listening on %s and 127.0.0.1:%d",
            self.sock_path,
            tcp_port,
        )

        if on_started is not None:
            on_started(tcp_port)

        async with unix_server, tcp_server:
            await asyncio.gather(
                unix_server.serve_forever(),
                tcp_server.serve_forever(),
            )

    # ------------------------------------------------------------------
    # Connection dispatcher
    # ------------------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            if line.upper().startswith(b"CONNECT "):
                await self._handle_connect(reader, writer, line)
            else:
                await self._handle_http(reader, writer, line)
        except Exception:
            logger.debug("Client handler error", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Plain HTTP proxy
    # ------------------------------------------------------------------

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
    ) -> None:
        try:
            import aiohttp
        except ImportError:
            writer.write(b"HTTP/1.1 501 aiohttp not installed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        # Read remaining headers
        header_lines = [first_line]
        while True:
            line = await reader.readline()
            header_lines.append(line)
            if line in (b"\r\n", b"\n", b""):
                break

        req_line = first_line.decode("latin-1", errors="replace").rstrip("\r\n")
        parts = req_line.split(" ", 2)
        if len(parts) < 2:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        method, url = parts[0], parts[1]

        # Parse headers
        raw_headers: dict[str, str] = {}
        content_length = 0
        for h_bytes in header_lines[1:]:
            h = h_bytes.decode("latin-1", errors="replace").strip()
            if ":" in h:
                k, v = h.split(":", 1)
                raw_headers[k.strip()] = v.strip()
                if k.strip().lower() == "content-length":
                    try:
                        content_length = int(v.strip())
                    except ValueError:
                        pass

        # Read body
        body = b""
        if content_length > 0:
            try:
                body = await reader.readexactly(content_length)
            except asyncio.IncompleteReadError as exc:
                body = exc.partial

        # Substitute in header values
        sub_headers: dict[str, str] = {}
        for k, v in raw_headers.items():
            new_v = substitute(v, self.store)
            if new_v != v:
                logger.debug("Substituted credential in request header %r", k)
            sub_headers[k] = new_v

        # Substitute in body
        body_str = body.decode("utf-8", errors="replace")
        sub_body_str = substitute(body_str, self.store)
        if sub_body_str != body_str:
            logger.debug("Substituted credential in request body")
        sub_body = sub_body_str.encode("utf-8", errors="replace") if sub_body_str != body_str else body

        forward_headers = {
            k: v for k, v in sub_headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

        # Recalculate Content-Length if body changed after substitution
        if len(sub_body) != len(body):
            cl_key = next(
                (k for k in forward_headers if k.lower() == "content-length"),
                "Content-Length",
            )
            forward_headers[cl_key] = str(len(sub_body))
            logger.debug(
                "Updated Content-Length from %d to %d after body substitution",
                len(body),
                len(sub_body),
            )

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.request(
                    method,
                    url,
                    headers=forward_headers,
                    data=sub_body if sub_body else None,
                    allow_redirects=False,
                ) as resp:
                    status_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                    writer.write(status_line.encode("latin-1", errors="replace"))
                    for k, v in resp.headers.items():
                        if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                            writer.write(f"{k}: {v}\r\n".encode("latin-1", errors="replace"))
                    resp_body = await resp.read()
                    writer.write(f"Content-Length: {len(resp_body)}\r\n".encode())
                    writer.write(b"\r\n")
                    writer.write(resp_body)
                    await writer.drain()
        except Exception:
            logger.debug("HTTP forward error", exc_info=True)
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # HTTPS CONNECT MITM
    # ------------------------------------------------------------------

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
    ) -> None:
        parts = first_line.split()
        if len(parts) < 2:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        host_port = parts[1].decode("latin-1", errors="replace")
        host, _, port_s = host_port.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443

        # Drain CONNECT request headers
        while True:
            line = await reader.readline()
            if not line.strip():
                break

        # Acknowledge the tunnel
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Detach the raw socket from asyncio so we can wrap it with ssl
        raw_sock = writer.transport.get_extra_info("socket")
        try:
            raw_sock = raw_sock.dup()
        except Exception:
            logger.debug("Failed to dup socket for MITM", exc_info=True)
            return
        writer.transport.close()

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._mitm_thread, raw_sock, host, port)
        except Exception:
            logger.debug("MITM executor error", exc_info=True)

    def _mitm_thread(self, raw_sock: socket.socket, host: str, port: int) -> None:
        """Synchronous MITM handler — runs in a thread-pool executor."""
        cert_pem, key_pem = self.ca.issue_cert(host)

        cert_file = key_file = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
                cf.write(cert_pem)
                cert_file = cf.name
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
                kf.write(key_pem)
                key_file = kf.name

            ssl_ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx_server.load_cert_chain(cert_file, key_file)
        finally:
            for path in (cert_file, key_file):
                if path:
                    try:
                        os.unlink(path)
                    except Exception:
                        pass

        # Wrap client socket — we act as TLS server
        try:
            client_ssl = ssl_ctx_server.wrap_socket(raw_sock, server_side=True)
        except ssl.SSLError:
            logger.debug("TLS wrap failed for %s client side", host, exc_info=True)
            try:
                raw_sock.close()
            except Exception:
                pass
            return

        # Connect to the real server with TLS
        server_ssl = None
        try:
            server_sock = socket.create_connection((host, port), timeout=30)
            ssl_ctx_client = ssl.create_default_context()
            server_ssl = ssl_ctx_client.wrap_socket(server_sock, server_hostname=host)
        except Exception:
            logger.debug("Failed to connect to %s:%s", host, port, exc_info=True)
            try:
                client_ssl.close()
            except Exception:
                pass
            return

        try:
            self._proxy_http_sync(client_ssl, server_ssl)
        finally:
            for sock in (client_ssl, server_ssl):
                try:
                    sock.close()
                except Exception:
                    pass

    def _proxy_http_sync(self, client_ssl, server_ssl) -> None:
        """Read HTTP requests from the MITM'd client, substitute, forward."""
        while True:
            req = _read_http_message_sync(client_ssl)
            if req is None:
                return

            headers_bytes, body_bytes = req

            # Substitute in headers
            headers_str = headers_bytes.decode("latin-1", errors="replace")
            sub_headers_str = substitute(headers_str, self.store)
            if sub_headers_str != headers_str:
                logger.debug("Substituted credential in HTTPS request headers")
                sub_headers_bytes = sub_headers_str.encode("latin-1", errors="replace")
            else:
                sub_headers_bytes = headers_bytes

            # Substitute in body
            body_str = body_bytes.decode("utf-8", errors="replace")
            sub_body_str = substitute(body_str, self.store)
            if sub_body_str != body_str:
                logger.debug("Substituted credential in HTTPS request body")
                sub_body_bytes = sub_body_str.encode("utf-8", errors="replace")
            else:
                sub_body_bytes = body_bytes

            # Recalculate Content-Length if body changed after substitution
            if len(sub_body_bytes) != len(body_bytes):
                new_len = len(sub_body_bytes)
                sub_headers_bytes = re.sub(
                    rb"(?i)(content-length:\s*)\d+",
                    lambda m: m.group(1) + str(new_len).encode(),
                    sub_headers_bytes,
                )
                logger.debug(
                    "Updated Content-Length to %d after HTTPS body substitution",
                    new_len,
                )

            try:
                server_ssl.sendall(sub_headers_bytes + sub_body_bytes)
            except Exception:
                return

            resp = _read_http_message_sync(server_ssl)
            if resp is None:
                return

            resp_headers_bytes, resp_body_bytes = resp
            try:
                client_ssl.sendall(resp_headers_bytes + resp_body_bytes)
            except Exception:
                return

            # Honour Connection: close
            resp_header_str = resp_headers_bytes.decode("latin-1", errors="replace").lower()
            if "connection: close" in resp_header_str:
                return


# ---------------------------------------------------------------------------
# Sync HTTP message reader (for MITM thread)
# ---------------------------------------------------------------------------

def _read_http_message_sync(sock) -> tuple[bytes, bytes] | None:
    """Read a complete HTTP message from a raw/SSL socket.

    Returns (header_bytes_including_blank_line, body_bytes) or None on error.
    """
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(4096)
        except Exception:
            return None
        if not chunk:
            return None
        data += chunk
        if len(data) > _BODY_READ_LIMIT:
            return None

    sep = data.find(b"\r\n\r\n")
    headers_bytes = data[: sep + 4]
    extra = data[sep + 4:]

    headers_str = headers_bytes.decode("latin-1", errors="replace")
    content_length = 0
    is_chunked = False
    for line in headers_str.split("\r\n"):
        ll = line.lower()
        if ll.startswith("content-length:"):
            try:
                content_length = int(ll.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif ll.startswith("transfer-encoding:") and "chunked" in ll:
            is_chunked = True

    body = extra
    if is_chunked:
        while not _chunked_complete(body):
            try:
                chunk = sock.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            body += chunk
            if len(body) > _BODY_READ_LIMIT:
                break
    elif content_length > 0:
        while len(body) < content_length:
            need = content_length - len(body)
            try:
                chunk = sock.recv(min(4096, need))
            except Exception:
                break
            if not chunk:
                break
            body += chunk

    return headers_bytes, body


def _chunked_complete(data: bytes) -> bool:
    """Return True if chunked-encoded *data* ends with the terminal chunk."""
    return data.endswith(b"0\r\n\r\n")
