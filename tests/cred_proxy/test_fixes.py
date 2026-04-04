"""Tests for specific bug fixes in the credential proxy."""

import asyncio
import os
from unittest.mock import patch

import pytest


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


# ---------------------------------------------------------------------------
# Fix: stop() preserves state files on PermissionError
# ---------------------------------------------------------------------------

def test_stop_preserves_files_on_permission_error(tmp_path, monkeypatch):
    """stop() leaves PID/port files intact when os.kill raises PermissionError."""
    import cred_proxy.daemon as daemon_module

    pid_file = tmp_path / "cred-proxy.pid"
    port_file = tmp_path / "cred-proxy.port"

    monkeypatch.setattr(daemon_module, "_PID_FILE", pid_file)
    monkeypatch.setattr(daemon_module, "_PORT_FILE", port_file)
    monkeypatch.setattr(daemon_module, "_STATE_DIR", tmp_path)

    pid_file.write_text("12345")
    port_file.write_text("8080")

    with patch("os.kill", side_effect=PermissionError("Operation not permitted")):
        daemon_module.stop()

    assert pid_file.exists(), "PID file should be preserved on PermissionError"
    assert port_file.exists(), "Port file should be preserved on PermissionError"


def test_stop_cleans_files_on_success(tmp_path, monkeypatch):
    """stop() removes PID/port files after a successful SIGTERM."""
    import cred_proxy.daemon as daemon_module

    pid_file = tmp_path / "cred-proxy.pid"
    port_file = tmp_path / "cred-proxy.port"

    monkeypatch.setattr(daemon_module, "_PID_FILE", pid_file)
    monkeypatch.setattr(daemon_module, "_PORT_FILE", port_file)
    monkeypatch.setattr(daemon_module, "_STATE_DIR", tmp_path)

    pid_file.write_text("12345")
    port_file.write_text("8080")

    with patch("os.kill"):
        daemon_module.stop()

    assert not pid_file.exists(), "PID file should be removed after successful stop"
    assert not port_file.exists(), "Port file should be removed after successful stop"


# ---------------------------------------------------------------------------
# Fix: run_proxy port=0 passes actual port to on_started callback
# ---------------------------------------------------------------------------

def test_run_proxy_port_zero_reports_actual_port():
    """run_proxy(port=0) passes a real port number to the on_started callback."""
    from cred_proxy.server import run_proxy
    from cred_proxy.store import CredStore

    reported_port = None

    def on_started(port: int) -> None:
        nonlocal reported_port
        reported_port = port

    async def _run():
        store = CredStore()
        server_task = asyncio.create_task(
            run_proxy(port=0, on_started=on_started, store=store)
        )
        # Give the server a moment to bind
        await asyncio.sleep(0.1)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())

    assert reported_port is not None, "on_started was never called"
    assert isinstance(reported_port, int)
    assert reported_port > 0, f"Expected a real port, got {reported_port}"
