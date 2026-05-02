"""
agentid — Cryptographic identity for AI agents.

Gives every AI agent an Ed25519 keypair and compact binary tokens that any
service can verify offline in <0.1 ms with zero network calls.

Quick start::

    from agentid import AgentIdentity, verify_token

    identity = AgentIdentity("research-bot", "phd-lab")
    token = identity.mint_token(scopes=["read:arxiv", "write:notes"], ttl_seconds=900)
    claims = verify_token(token, identity.public_key)
    print(claims.fingerprint)  # ag:sha256:022a6b57...
"""

__version__ = "0.1.0"

from agentid.identity import AgentIdentity
from agentid.token import AgentClaims, verify_token, scope_matches

__all__ = [
    "__version__",
    "AgentIdentity",
    "AgentClaims",
    "verify_token",
    "scope_matches",
]
