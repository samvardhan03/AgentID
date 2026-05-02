"""
agentid.integrations.crewai — Agent authentication for CrewAI crews.

Provides two integration patterns:

1. **AgentIDCrewMixin** (blueprint pattern) — a mixin that reads the
   ``agentid`` kwarg on Agent construction and attaches identity metadata.
2. **agentid_authenticate** — a decorator for agent factory functions.

Usage (blueprint pattern)::

    from crewai import Agent
    from agentid import AgentIdentity
    from agentid.integrations.crewai import AgentIDCrewMixin

    researcher = Agent(
        role="researcher",
        agentid=AgentIdentity(name="researcher", project="crew-v1")
    )

Usage (decorator pattern)::

    from agentid.integrations.crewai import agentid_authenticate

    @agentid_authenticate(identity=identity, scopes=["read:arxiv"])
    def create_researcher():
        return Agent(role="Senior Researcher", goal="...", backstory="...")
"""

from __future__ import annotations

import functools
from typing import Any, Callable, List, Optional, Sequence, TypeVar

from agentid.identity import AgentIdentity
from agentid.token import AgentClaims, verify_token

F = TypeVar("F", bound=Callable[..., Any])


class AgentIDCrewMixin:
    """Mixin that binds an AgentID identity to a CrewAI Agent.

    Matches the blueprint pattern where identity is passed as a kwarg::

        agent = Agent(
            role="researcher",
            agentid=AgentIdentity(name="researcher", project="crew-v1")
        )

    The mixin reads the ``agentid`` kwarg, mints a fresh token, and stores
    identity metadata on the agent instance.

    Parameters
    ----------
    identity : AgentIdentity
        The agent's cryptographic identity.
    scopes : Sequence[str]
        Permission scopes for the auto-minted token.
    ttl_seconds : int
        Token lifetime (default 15 minutes).
    max_calls : int
        Per-token call quota (0 = unlimited).
    """

    @staticmethod
    def attach(
        agent: Any,
        identity: AgentIdentity,
        scopes: Sequence[str] = (),
        ttl_seconds: int = 900,
        max_calls: int = 0,
    ) -> Any:
        """Attach AgentID identity and a fresh token to an agent instance."""
        token = identity.mint_token(
            scopes=list(scopes),
            ttl_seconds=ttl_seconds,
            max_calls=max_calls,
        )
        agent._agentid_identity = identity
        agent._agentid_token = token
        agent._agentid_scopes = list(scopes)
        return agent


def agentid_authenticate(
    *,
    identity: AgentIdentity,
    scopes: Sequence[str] = (),
    ttl_seconds: int = 900,
    max_calls: int = 0,
) -> Callable[[F], F]:
    """Decorator that attaches an AgentID identity and fresh token to a CrewAI Agent.

    The decorated function must return a CrewAI ``Agent`` instance.  The
    decorator mints a token and attaches both the identity and the token to the
    agent as private attributes.

    Parameters
    ----------
    identity : AgentIdentity
        The agent's cryptographic identity.
    scopes : Sequence[str]
        Permission scopes baked into the token.
    ttl_seconds : int
        Token lifetime (default 15 minutes).
    max_calls : int
        Per-token call quota (0 = unlimited).
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            agent = fn(*args, **kwargs)

            # Mint a fresh token for this agent's session.
            token = identity.mint_token(
                scopes=list(scopes),
                ttl_seconds=ttl_seconds,
                max_calls=max_calls,
            )

            # Attach identity metadata to the agent instance.
            agent._agentid_identity = identity
            agent._agentid_token = token
            agent._agentid_scopes = list(scopes)

            return agent

        return wrapper  # type: ignore[return-value]

    return decorator


def get_agent_claims(agent: Any) -> Optional[AgentClaims]:
    """Extract and verify the AgentID claims from a decorated CrewAI agent.

    Returns ``None`` if the agent doesn't have AgentID metadata or if the
    token is invalid/expired.

    Parameters
    ----------
    agent : Any
        A CrewAI ``Agent`` that was decorated with :func:`agentid_authenticate`.
    """
    token = getattr(agent, "_agentid_token", None)
    identity = getattr(agent, "_agentid_identity", None)
    if token is None or identity is None:
        return None

    try:
        return verify_token(token, expected_pubkey=identity.public_key)
    except Exception:
        return None


def verify_agent_scope(agent: Any, required_scope: str) -> bool:
    """Check whether a decorated CrewAI agent's token covers a scope.

    Parameters
    ----------
    agent : Any
        A CrewAI ``Agent`` decorated with :func:`agentid_authenticate`.
    required_scope : str
        The scope to check (e.g. ``"write:notes"``).

    Returns
    -------
    bool
        ``True`` if the agent has a valid token that covers the scope.
    """
    claims = get_agent_claims(agent)
    if claims is None:
        return False
    return claims.permits(required_scope)
