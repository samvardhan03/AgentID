"""
agentid.token — Token verification and scope matching.

Wraps the native ``verify_token`` and ``scope_matches`` functions with
Pythonic signatures, full type annotations, and dataclass-based claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from agentid._native import scope_matches as _native_scope_matches
from agentid._native import verify_token as _native_verify_token


@dataclass(frozen=True)
class AgentClaims:
    """Decoded token claims returned by :func:`verify_token`.

    Attributes
    ----------
    name : str
        Agent name embedded in the token.
    project : str
        Project namespace.
    scopes : list[str]
        Granted permission scopes.
    issued_at : int
        Unix timestamp when the token was minted.
    expires_at : int
        Unix timestamp when the token expires.
    max_calls : int
        Per-token call quota (0 = unlimited).
    token_id : int
        Random nonce for replay protection.
    issuer : bytes
        32-byte Ed25519 public key of the issuer.
    fingerprint : str
        Human-readable fingerprint of the issuer.
    """

    name: str
    project: str
    scopes: List[str]
    issued_at: int
    expires_at: int
    max_calls: int
    token_id: int
    issuer: bytes
    fingerprint: str

    def permits(self, scope: str) -> bool:
        """Check whether this token's scopes cover ``scope``.

        Uses the same wildcard rules as the Rust core:
        ``"read:*"`` matches ``"read:arxiv"``, etc.
        """
        return any(scope_matches(g, scope) for g in self.scopes)


def verify_token(
    token: bytes,
    expected_pubkey: Optional[bytes] = None,
) -> AgentClaims:
    """Verify a token's signature and expiry, then return its claims.

    Parameters
    ----------
    token : bytes
        Raw binary token (as returned by ``AgentIdentity.mint_token``).
    expected_pubkey : bytes | None
        If provided (32 bytes), the token's embedded issuer must match.

    Returns
    -------
    AgentClaims
        Decoded and verified claims.

    Raises
    ------
    RuntimeError
        If the token is malformed, expired, or the signature is invalid.
    ValueError
        If *expected_pubkey* is not exactly 32 bytes.
    """
    raw: dict = _native_verify_token(token, expected_pubkey)
    return AgentClaims(
        name=raw["name"],
        project=raw["project"],
        scopes=raw["scopes"],
        issued_at=raw["issued_at"],
        expires_at=raw["expires_at"],
        max_calls=raw["max_calls"],
        token_id=raw["token_id"],
        issuer=bytes(raw["issuer"]),
        fingerprint=raw["fingerprint"],
    )


def scope_matches(granted: str, requested: str) -> bool:
    """Check whether *granted* scope covers *requested*.

    Wildcard rules::

        "read:arxiv"  → matches "read:arxiv" exactly
        "read:*"      → matches "read:arxiv", "read:notes", …
        "*"           → matches everything
        "*:papers"    → matches "read:papers", "write:papers"

    Parameters
    ----------
    granted : str
        Scope string from the token.
    requested : str
        Scope the caller wants to use.

    Returns
    -------
    bool
    """
    return _native_scope_matches(granted, requested)
