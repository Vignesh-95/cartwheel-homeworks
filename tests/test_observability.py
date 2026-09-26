"""Authentication tests for the Homework 2 session and token machinery.

Everything here runs offline: no Langfuse, no Docker, no model provider key.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from server import app as server_app


def test_create_session_rejects_role_mismatch(world: dict) -> None:
    """The database says user 1 is a shopper; claiming 'merchant' must be refused."""
    server_app._SESSIONS.clear()
    with pytest.raises(HTTPException) as exc_info:
        server_app.create_session(server_app.SessionCreate(user_id=1, role="merchant"))
    assert exc_info.value.status_code == 403


def test_token_cannot_authorize_a_different_session(world: dict) -> None:
    """A token minted for session A must not pass authorization for session B."""
    server_app._SESSIONS.clear()
    session_a = server_app.create_session(server_app.SessionCreate(user_id=1, role="shopper"))
    session_b = server_app.create_session(
        server_app.SessionCreate(user_id=9002, role="merchant")
    )

    with pytest.raises(HTTPException) as exc_info:
        server_app._authorize(session_b["session_id"], f"Bearer {session_a['token']}")
    assert exc_info.value.status_code == 403
