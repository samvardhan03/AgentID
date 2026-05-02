"""Tests for agentid.token — verify_token and scope_matches."""

import pytest
from agentid import AgentIdentity, verify_token, scope_matches
from agentid.token import AgentClaims


class TestVerifyToken:
    def test_round_trip(self):
        identity = AgentIdentity("research-bot", "phd-lab")
        token = identity.mint_token(
            scopes=["read:arxiv", "write:notes"],
            ttl_seconds=60,
            max_calls=100,
        )
        claims = verify_token(token, expected_pubkey=identity.public_key)
        assert isinstance(claims, AgentClaims)
        assert claims.name == "research-bot"
        assert claims.project == "phd-lab"
        assert claims.scopes == ["read:arxiv", "write:notes"]
        assert claims.max_calls == 100
        assert claims.issuer == identity.public_key
        assert claims.fingerprint == identity.fingerprint

    def test_token_size_under_200(self):
        identity = AgentIdentity("research-bot", "phd-lab")
        token = identity.mint_token(
            scopes=["read:arxiv", "write:notes"],
            ttl_seconds=900,
            max_calls=100,
        )
        assert len(token) < 200

    def test_verify_without_expected_pubkey(self):
        identity = AgentIdentity("bot", "proj")
        token = identity.mint_token(scopes=["read:*"], ttl_seconds=60)
        claims = verify_token(token)
        assert claims.name == "bot"

    def test_rejects_tampered_token(self):
        identity = AgentIdentity("bot", "proj")
        token = bytearray(identity.mint_token(scopes=["read:arxiv"], ttl_seconds=60))
        token[70] ^= 0xFF  # flip a byte
        with pytest.raises(RuntimeError):
            verify_token(bytes(token), expected_pubkey=identity.public_key)

    def test_rejects_issuer_mismatch(self):
        a = AgentIdentity("bot-a", "proj")
        b = AgentIdentity("bot-b", "proj")
        token = a.mint_token(ttl_seconds=60)
        with pytest.raises(RuntimeError, match="[Ii]ssuer"):
            verify_token(token, expected_pubkey=b.public_key)

    def test_invalid_pubkey_length(self):
        identity = AgentIdentity("bot", "proj")
        token = identity.mint_token(ttl_seconds=60)
        with pytest.raises(ValueError, match="32 bytes"):
            verify_token(token, expected_pubkey=b"short")

    def test_unique_token_ids(self):
        identity = AgentIdentity("bot", "proj")
        t1 = identity.mint_token(ttl_seconds=60)
        t2 = identity.mint_token(ttl_seconds=60)
        c1 = verify_token(t1)
        c2 = verify_token(t2)
        assert c1.token_id != c2.token_id


class TestScopeMatches:
    def test_exact_match(self):
        assert scope_matches("read:arxiv", "read:arxiv") is True

    def test_wildcard_suffix(self):
        assert scope_matches("read:*", "read:arxiv") is True

    def test_wildcard_prefix(self):
        assert scope_matches("*:papers", "read:papers") is True

    def test_full_wildcard(self):
        assert scope_matches("*", "anything:goes") is True

    def test_no_match(self):
        assert scope_matches("read:arxiv", "write:arxiv") is False

    def test_segment_count_mismatch(self):
        assert scope_matches("read:arxiv", "read:arxiv:v2") is False


class TestAgentClaimsPermits:
    def test_permits_with_wildcard(self):
        identity = AgentIdentity("bot", "proj")
        token = identity.mint_token(scopes=["read:*"], ttl_seconds=60)
        claims = verify_token(token)
        assert claims.permits("read:arxiv") is True
        assert claims.permits("write:arxiv") is False
