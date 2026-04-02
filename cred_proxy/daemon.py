"""Credential proxy daemon lifecycle management.

start()     — spawn the proxy as a detached background process, wait for PID
stop()      — SIGTERM the daemon, remove PID file
status()    — return {running, pid, socket, port}
is_running()— quick bool check used by other components
"""

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

_STATE_DIR = Path.home() / ".hermes" / "state"
_PID_FILE = _STATE_DIR / "cred-proxy.pid"
_PORT_FILE = _STATE_DIR / "cred-proxy.port"
_SOCK_PATH = _STATE_DIR / "cred-proxy.sock"
_LOG_FILE = _STATE_DIR / "cred-proxy.log"


# ---------------------------------------------------------------------------
# PID file helpers
# ---------------------------------------------------------------------------

def _write_pid() -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(os.getpid()))


def _read_pid() -> int | None:
    try:
        return int(_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def _remove_pid() -> None:
    try:
        _PID_FILE.unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Port file helpers
# ---------------------------------------------------------------------------

def _write_port(port: int) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _PORT_FILE.write_text(str(port))


def _read_port() -> int | None:
    try:
        return int(_PORT_FILE.read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def _remove_port() -> None:
    try:
        _PORT_FILE.unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_running() -> bool:
    """Return True if the credential proxy daemon is running.

    Checks that both PID file and port file exist and that the process is
    alive.  Removes stale files if the process is dead.
    """
    pid = _read_pid()
    if pid is None:
        return False
    port = _read_port()
    if port is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        # Process is dead — clean up stale files
        _remove_pid()
        _remove_port()
        return False
    except PermissionError:
        # Process exists but we can't send signals — still running
        return True


def status() -> dict:
    """Return {running: bool, pid: int|None, socket: str, port: int|None}."""
    running = is_running()
    return {
        "running": running,
        "pid": _read_pid() if running else None,
        "socket": str(_SOCK_PATH),
        "port": _read_port() if running else None,
    }


def stop() -> None:
    """Send SIGTERM to the daemon and remove the PID and port files."""
    pid = _read_pid()
    if pid is None:
        print("Credential proxy is not running.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped credential proxy (PID {pid}).")
    except ProcessLookupError:
        print("Credential proxy process not found (already stopped?).")
    except PermissionError:
        print(f"Permission denied when signalling PID {pid}.")
    finally:
        _remove_pid()
        _remove_port()


def start() -> None:
    """Start the credential proxy daemon as a detached background process.

    Spawns ``python -m cred_proxy`` with start_new_session=True so it
    survives the calling process exiting.  Waits up to 3 s for the daemon
    to write its PID and port files before returning.
    """
    if is_running():
        print("Credential proxy is already running.")
        return

    import subprocess
    import time

    cmd = [sys.executable, "-m", "cred_proxy"]
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        print(f"Failed to start credential proxy: {exc}")
        return

    # Wait up to 3 s for the daemon to write its PID and port files
    for _ in range(30):
        time.sleep(0.1)
        if is_running():
            pid = _read_pid()
            print(f"Credential proxy started (PID {pid}).")
            return

    print("Warning: Could not confirm credential proxy started. Check logs at:")
    print(f"  {_LOG_FILE}")


# ---------------------------------------------------------------------------
# Internal: run the server (called from __main__.py)
# ---------------------------------------------------------------------------

def _run_server() -> None:
    """Configure logging and run the asyncio proxy server (blocks forever).

    Binds both the Unix socket and a localhost TCP port before writing the
    PID and port files, so callers polling is_running() only see the daemon
    as ready once it is fully bound.
    """
    from .ca import LocalCA
    from .server import CredProxy
    from .store import CredStore

    logging.basicConfig(
        filename=str(_LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    def _on_sigterm(signum, frame):
        _remove_pid()
        _remove_port()
        if _SOCK_PATH.exists():
            try:
                _SOCK_PATH.unlink()
            except Exception:
                pass
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except (OSError, ValueError):
        pass  # Windows or restricted environment

    def _on_started(port: int) -> None:
        """Called by CredProxy.start() after both sockets are bound."""
        _write_pid()
        _write_port(port)

    store = CredStore()
    ca = LocalCA()
    proxy = CredProxy(store, ca, str(_SOCK_PATH))

    try:
        asyncio.run(proxy.start(on_started=_on_started))
    finally:
        _remove_pid()
        _remove_port()
        try:
            if _SOCK_PATH.exists():
                _SOCK_PATH.unlink()
        except Exception:
            pass
