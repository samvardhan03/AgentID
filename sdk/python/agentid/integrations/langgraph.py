"""
agentid.integrations.langgraph — Authentication for LangGraph agent pipelines.

Provides two integration patterns:

1. **AgentIDLangGraphMiddleware** (blueprint pattern) — auto-attaches an
   AgentID identity and mints tokens into graph state.
2. **agentid_auth_node** — a graph node that verifies tokens already in state.

Usage::

    from langgraph.graph import StateGraph
    from agentid.integrations.langgraph import AgentIDLangGraphMiddleware

    graph = StateGraph(AgentState)
    graph.add_middleware(AgentIDLangGraphMiddleware(name="my-agent", project="my-project"))
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence, TypeVar

from agentid.identity import AgentIdentity
from agentid.token import AgentClaims, verify_token

# Type alias for LangGraph state dicts.
State = Dict[str, Any]

T = TypeVar("T")


class AgentIDLangGraphMiddleware:
    """LangGraph middleware that auto-attaches AgentID tokens to graph state.

    This matches the blueprint's ``AgentIDMiddleware`` pattern: create an
    identity from ``(name, project)`` and inject a fresh token into the
    graph state before every node invocation.

    Parameters
    ----------
    name : str
        Agent name for identity derivation.
    project : str
        Project namespace.
    scopes : Sequence[str]
        Permission scopes baked into the token.
    ttl_seconds : int
        Token lifetime (default 15 minutes).
    max_calls : int
        Per-token call quota (0 = unlimited).
    token_key : str
        State dict key where the token is stored.
    claims_key : str
        State dict key where verified claims are stored.
    """

    def __init__(
        self,
        name: str,
        project: str,
        scopes: Sequence[str] = (),
        ttl_seconds: int = 900,
        max_calls: int = 0,
        token_key: str = "agentid_token",
        claims_key: str = "agentid_claims",
    ) -> None:
        self.identity = AgentIdentity(name, project)
        self.scopes = list(scopes)
        self.ttl_seconds = ttl_seconds
        self.max_calls = max_calls
        self.token_key = token_key
        self.claims_key = claims_key

    def inject(self, state: State) -> State:
        """Mint a fresh token and inject it (plus verified claims) into state."""
        token = self.identity.mint_token(
            scopes=self.scopes,
            ttl_seconds=self.ttl_seconds,
            max_calls=self.max_calls,
        )
        claims = verify_token(token, self.identity.public_key)
        state[self.token_key] = token
        state[self.claims_key] = claims
        return state


# Blueprint alias
AgentIDMiddleware = AgentIDLangGraphMiddleware


def agentid_auth_node(
    *,
    trusted_keys: Optional[List[bytes]] = None,
    required_scopes: Optional[List[str]] = None,
    token_key: str = "agentid_token",
    claims_key: str = "agentid_claims",
    error_key: str = "agentid_error",
) -> Callable[[State], State]:
    """Create a LangGraph node function that verifies an AgentID token.

    The node reads a raw token from ``state[token_key]``, verifies it, and
    writes the decoded claims to ``state[claims_key]``.  On failure it writes
    the error string to ``state[error_key]`` instead.

    Parameters
    ----------
    trusted_keys : list[bytes] | None
        Allowed issuer public keys (32 bytes each).  If ``None``, any
        valid signature is accepted (self-issued tokens pass).
    required_scopes : list[str] | None
        Scopes the token must cover.  Checked after signature verification.
    token_key : str
        State dict key where the raw token ``bytes`` lives.
    claims_key : str
        State dict key where the verified :class:`AgentClaims` is stored.
    error_key : str
        State dict key where error messages are stored on failure.
    """

    def _node(state: State) -> State:
        token: Optional[bytes] = state.get(token_key)
        if token is None:
            return {error_key: f"Missing '{token_key}' in graph state"}

        # Try each trusted key; fall back to no-key verification.
        claims: Optional[AgentClaims] = None
        last_err: Optional[str] = None

        if trusted_keys:
            for pk in trusted_keys:
                try:
                    claims = verify_token(token, pk)
                    break
                except Exception as exc:
                    last_err = str(exc)
        else:
            try:
                claims = verify_token(token)
            except Exception as exc:
                last_err = str(exc)

        if claims is None:
            return {error_key: f"Token verification failed: {last_err}"}

        # Scope enforcement.
        if required_scopes:
            for scope in required_scopes:
                if not claims.permits(scope):
                    return {
                        error_key: (
                            f"Scope '{scope}' not granted. "
                            f"Token scopes: {claims.scopes}"
                        )
                    }

        return {claims_key: claims}

    _node.__name__ = "agentid_auth_node"
    _node.__doc__ = "Verify an AgentID token in the graph state."
    return _node
