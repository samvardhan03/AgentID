"""
agentid.identity — Pythonic wrapper around the native AgentIdentity.

This module provides a high-level, fully-typed ``AgentIdentity`` class that
delegates all cryptographic operations to the compiled Rust core via PyO3.
"""

from __future__ import annotations

from typing import Optional, Sequence

from agentid._native import AgentIdentity as _NativeIdentity


class AgentIdentity:
    """A cryptographic agent identity backed by an Ed25519 keypair.

    Identities are deterministic: the same ``(name, project)`` pair always
    produces the same keypair, on every machine.

    Parameters
    ----------
    name : str
        Human-readable agent name (max 255 bytes).
    project : str
        Project or namespace (max 255 bytes).
    seed : bytes | None
        Optional extra entropy.  Pass random bytes to create an ephemeral
        identity that's still labelled with *name*/*project*.

    Examples
    --------
    >>> from agentid import AgentIdentity
    >>> identity = AgentIdentity("research-bot", "phd-lab")
    >>> identity.fingerprint
    'ag:sha256:022a6b57...'
    """

    __slots__ = ("_native",)

    def __init__(
        self,
        name: str,
        project: str,
        seed: Optional[bytes] = None,
    ) -> None:
        self._native = _NativeIdentity(name, project, seed)

    @classmethod
    def from_secret_bytes(
        cls,
        name: str,
        project: str,
        secret_bytes: bytes,
    ) -> "AgentIdentity":
        """Reconstruct an identity from a raw 32-byte Ed25519 secret key.

        Parameters
        ----------
        name : str
            Agent name.
        project : str
            Project namespace.
        secret_bytes : bytes
            32-byte Ed25519 secret key.
        """
        obj = cls.__new__(cls)
        obj._native = _NativeIdentity.from_secret_bytes(name, project, secret_bytes)
        return obj

    # -- Properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        """Agent name."""
        return self._native.name

    @property
    def project(self) -> str:
        """Project namespace."""
        return self._native.project

    @property
    def public_key(self) -> bytes:
        """32-byte Ed25519 public key."""
        return bytes(self._native.public_key)

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded public key."""
        return self._native.public_key_hex

    @property
    def secret_bytes(self) -> bytes:
        """32-byte Ed25519 secret key.  **Treat as sensitive.**"""
        return bytes(self._native.secret_bytes)

    @property
    def fingerprint(self) -> str:
        """Human-readable fingerprint: ``ag:sha256:<16 hex chars>``."""
        return self._native.fingerprint

    # -- Methods -------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign an arbitrary message.

        Returns a 64-byte Ed25519 signature.
        """
        return bytes(self._native.sign(message))

    def mint_token(
        self,
        *,
        scopes: Sequence[str] = (),
        ttl_seconds: int = 900,
        max_calls: int = 0,
    ) -> bytes:
        """Mint a compact binary token (~173 bytes).

        Parameters
        ----------
        scopes : Sequence[str]
            Permission scopes, e.g. ``["read:arxiv", "write:notes"]``.
        ttl_seconds : int
            Token lifetime in seconds (1–86 400).  Default 900 (15 min).
        max_calls : int
            Per-token call quota.  0 = unlimited.

        Returns
        -------
        bytes
            Raw binary token ready for transmission.
        """
        return bytes(
            self._native.mint_token(
                scopes=list(scopes),
                ttl_seconds=ttl_seconds,
                max_calls=max_calls,
            )
        )

    def __repr__(self) -> str:
        return (
            f"AgentIdentity(name={self.name!r}, project={self.project!r}, "
            f"fingerprint={self.fingerprint!r})"
        )
