"""Credential placeholder substitution.

Replaces ``hermes-proxy://<name>`` tokens in strings with the real credential
values from the store.  Unknown names are left unchanged so that unset
credentials surface as visible errors in downstream requests rather than
silently sending the placeholder string.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import CredStore

_PLACEHOLDER_RE = re.compile(r"hermes-proxy://([A-Za-z0-9_\-\.]+)")


def substitute(data: str, store: "CredStore") -> str:
    """Replace ``hermes-proxy://<name>`` in *data* with real credential values.

    Works on any string: header values, JSON bodies, query strings, etc.
    Unknown credential names are left as-is (placeholder unchanged).
    """

    def _replacer(match: re.Match) -> str:
        name = match.group(1)
        try:
            return store._get(name)
        except KeyError:
            return match.group(0)

    return _PLACEHOLDER_RE.sub(_replacer, data)
