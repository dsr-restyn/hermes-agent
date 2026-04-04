"""Tests for /btw bypass of the running-agent interrupt path.

Verifies that /btw is dispatched directly to _handle_btw_command even when
an agent is currently running — not sent as an interrupt to the active agent.

Regression test for: /btw treated as interrupt when agent is running.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.platforms.base import (
    MessageEvent,
    MessageType,
    Platform,
)
from gateway.session import SessionSource


def _make_source(chat_id="c1", user_id="u1"):
    return SessionSource(platform=Platform.TELEGRAM, user_id=user_id, chat_id=chat_id)


def _make_btw_event(question: str = "what is 2+2") -> MessageEvent:
    return MessageEvent(
        text=f"/btw {question}",
        source=_make_source(),
        message_id="m1",
        message_type=MessageType.TEXT,
    )


def _make_running_agent_mock() -> MagicMock:
    agent = MagicMock()
    agent.interrupt = MagicMock()
    return agent


# Key format: agent:main:<platform>:<chat_type>:<chat_id>
_SESSION_KEY = "agent:main:telegram:dm:c1"


def _make_runner_with_running_agent():
    """Build a minimal GatewayRunner stub with one active agent."""
    from gateway.run import GatewayRunner

    runner = GatewayRunner.__new__(GatewayRunner)
    runner.adapters = {}
    runner.hooks = MagicMock()
    runner.hooks.emit = AsyncMock()
    runner._pending_messages = {}
    runner._running_agents_ts = {}

    running_agent = _make_running_agent_mock()
    runner._running_agents = {_SESSION_KEY: running_agent}
    return runner, running_agent


class TestBtwBypassesRunningAgent:
    """/btw must be dispatched directly even when an agent is running."""

    @pytest.mark.asyncio
    async def test_btw_does_not_interrupt_running_agent(self):
        """Sending /btw while an agent is running should NOT call agent.interrupt()."""
        runner, running_agent = _make_runner_with_running_agent()
        event = _make_btw_event("what is 2+2")

        with patch.object(runner, "_is_user_authorized", return_value=True), \
             patch.object(
                 runner, "_handle_btw_command", new=AsyncMock(return_value="💬 answer")
             ) as mock_btw:
            await runner._handle_message(event)

        # /btw handler was called
        mock_btw.assert_called_once_with(event)
        # Running agent was NOT interrupted
        running_agent.interrupt.assert_not_called()
        # /btw message was NOT queued as a pending message
        assert _SESSION_KEY not in runner._pending_messages

    @pytest.mark.asyncio
    async def test_regular_message_still_interrupts_running_agent(self):
        """Non-/btw messages while agent is running should still trigger interrupt."""
        runner, running_agent = _make_runner_with_running_agent()

        event = MessageEvent(
            text="just a normal message",
            source=_make_source(),
            message_id="m2",
            message_type=MessageType.TEXT,
        )

        with patch.object(runner, "_is_user_authorized", return_value=True), \
             patch.object(runner, "_handle_btw_command", new=AsyncMock()) as mock_btw:
            await runner._handle_message(event)

        # Normal message should interrupt the agent
        running_agent.interrupt.assert_called_once()
        # /btw handler should NOT have been called
        mock_btw.assert_not_called()
