"""
agentid.integrations.fastapi — ASGI middleware and dependency for FastAPI.

Provides two integration patterns:

1. **Middleware** — ``AgentIDMiddleware`` validates every request that carries
   an ``Authorization: AgentID <hex-token>`` header.
2. **Dependency** — ``require_agent_auth(scopes=[...])`` returns a FastAPI
   decorator/dependency that enforces scopes on a per-route basis.

Usage::

    from fastapi import FastAPI, Depends
    from agentid import AgentIdentity
    from agentid.integrations.fastapi import AgentIDMiddleware, require_agent_auth

    identity = AgentIdentity("api-service", "prod")

    app = FastAPI()
    app.add_middleware(
        AgentIDMiddleware,
        trusted_keys=[identity.public_key],
    )

    @app.post("/api/data")
    @require_agent_auth(scopes=["read:data"])
    async def get_data(agent: VerifiedAgent):
        return {"agent": agent.name, "scopes": agent.scopes}
"""

from __future__ import annotations

import binascii
from typing import Any, Callable, List, Optional, Sequence

from agentid.token import AgentClaims, verify_token

# Lazy-imported at runtime to keep the base package dependency-free.
_starlette_available: Optional[bool] = None


def _check_starlette() -> None:
    global _starlette_available
    if _starlette_available is None:
        try:
            import starlette  # noqa: F401

            _starlette_available = True
        except ImportError:
            _starlette_available = False
    if not _starlette_available:
        raise ImportError(
            "FastAPI/Starlette is required for this middleware. "
            "Install with: pip install agentid[fastapi]"
        )


# ---------------------------------------------------------------------------
# Request-scoped state key
# ---------------------------------------------------------------------------
CLAIMS_STATE_KEY = "agentid_claims"


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------


class AgentIDMiddleware:
    """Starlette/FastAPI middleware that verifies AgentID tokens.

    Reads the ``Authorization`` header (format: ``AgentID <hex-encoded token>``)
    and verifies the token against one of the *trusted_keys*.  On success the
    decoded :class:`AgentClaims` is stored in ``request.state.agentid_claims``.

    Requests without an ``Authorization`` header are passed through (use
    ``require_scope`` on individual routes to enforce authentication).

    Parameters
    ----------
    app : ASGIApp
        The ASGI application.
    trusted_keys : list[bytes] | None
        Allowed issuer public keys.  ``None`` accepts any valid signature.
    """

    def __init__(
        self,
        app: Any,
        trusted_keys: Optional[List[bytes]] = None,
    ) -> None:
        _check_starlette()
        self.app = app
        self.trusted_keys = trusted_keys

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive)
        auth_header: Optional[str] = request.headers.get("authorization")

        if auth_header and auth_header.startswith("AgentID "):
            hex_token = auth_header[len("AgentID ") :]
            try:
                raw_token = binascii.unhexlify(hex_token)
            except (ValueError, binascii.Error):
                response = JSONResponse(
                    {"detail": "Malformed AgentID token (bad hex)"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

            claims = self._verify(raw_token)
            if claims is None:
                response = JSONResponse(
                    {"detail": "Invalid or expired AgentID token"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

            scope.setdefault("state", {})
            scope["state"][CLAIMS_STATE_KEY] = claims

        await self.app(scope, receive, send)

    def _verify(self, token: bytes) -> Optional[AgentClaims]:
        if self.trusted_keys:
            for pk in self.trusted_keys:
                try:
                    return verify_token(token, expected_pubkey=pk)
                except Exception:
                    continue
            return None
        else:
            try:
                return verify_token(token)
            except Exception:
                return None


# ---------------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------------


def require_scope(
    *scopes: str,
) -> Callable:
    """FastAPI dependency that enforces one or more AgentID scopes.

    Use as a route dependency::

        @app.get("/notes", dependencies=[Depends(require_scope("write:notes"))])
        async def create_note(): ...

    Or inject the claims::

        @app.get("/papers")
        async def list_papers(claims=Depends(require_scope("read:arxiv"))):
            print(claims.name)

    Parameters
    ----------
    *scopes : str
        Required scopes.  All must be covered by the token.

    Raises
    ------
    HTTPException (401)
        If no valid AgentID claims are present in the request.
    HTTPException (403)
        If the token doesn't cover all required scopes.
    """
    _check_starlette()

    async def _dependency(**kwargs: Any) -> AgentClaims:
        from starlette.requests import Request

        # FastAPI injects `request` automatically.
        request: Request = kwargs.get("request")  # type: ignore[assignment]
        if request is None:
            # Fallback — try positional.
            raise RuntimeError("require_scope must be used as a FastAPI Depends()")

        from fastapi import HTTPException

        claims: Optional[AgentClaims] = getattr(
            request.state, CLAIMS_STATE_KEY, None
        )
        if claims is None:
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid AgentID token",
            )

        for scope in scopes:
            if not claims.permits(scope):
                raise HTTPException(
                    status_code=403,
                    detail=f"Scope '{scope}' not granted. Token scopes: {claims.scopes}",
                )

        return claims

    # Rewrite the signature so FastAPI sees `request: Request` as a parameter.
    import inspect

    from starlette.requests import Request

    _dependency.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        parameters=[
            inspect.Parameter(
                "request",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Request,
            )
        ]
    )

    return _dependency


# Blueprint-specified aliases
VerifiedAgent = AgentClaims
"""Type alias for ``AgentClaims``, matching the blueprint's ``VerifiedAgent`` name."""

require_agent_auth = require_scope
"""Alias for ``require_scope``, matching the blueprint's ``require_agent_auth`` name."""
