"""Tests for agentid.identity — AgentIdentity wrapper."""

import pytest
from agentid import AgentIdentity


class TestDerivation:
    def test_deterministic(self):
        a = AgentIdentity("research-bot", "phd-lab")
        b = AgentIdentity("research-bot", "phd-lab")
        assert a.public_key == b.public_key
        assert a.fingerprint == b.fingerprint

    def test_different_projects_produce_different_keys(self):
        a = AgentIdentity("bot", "proj-a")
        b = AgentIdentity("bot", "proj-b")
        assert a.public_key != b.public_key

    def test_seed_changes_key(self):
        a = AgentIdentity("bot", "proj")
        b = AgentIdentity("bot", "proj", seed=b"extra")
        assert a.public_key != b.public_key

    def test_round_trip_secret_bytes(self):
        a = AgentIdentity("bot", "proj")
        b = AgentIdentity.from_secret_bytes("bot", "proj", a.secret_bytes)
        assert a.public_key == b.public_key

    def test_empty_name_raises(self):
        with pytest.raises(ValueError, match="empty"):
            AgentIdentity("", "proj")

    def test_empty_project_raises(self):
        with pytest.raises(ValueError, match="empty"):
            AgentIdentity("bot", "")


class TestProperties:
    def test_name_and_project(self):
        identity = AgentIdentity("research-bot", "phd-lab")
        assert identity.name == "research-bot"
        assert identity.project == "phd-lab"

    def test_public_key_is_32_bytes(self):
        identity = AgentIdentity("bot", "proj")
        assert isinstance(identity.public_key, bytes)
        assert len(identity.public_key) == 32

    def test_public_key_hex_matches(self):
        identity = AgentIdentity("bot", "proj")
        assert identity.public_key_hex == identity.public_key.hex()

    def test_fingerprint_format(self):
        identity = AgentIdentity("bot", "proj")
        fp = identity.fingerprint
        assert fp.startswith("ag:sha256:")
        assert len(fp) == len("ag:sha256:") + 16


class TestSigning:
    def test_sign_returns_64_bytes(self):
        identity = AgentIdentity("bot", "proj")
        sig = identity.sign(b"hello")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_different_messages_different_sigs(self):
        identity = AgentIdentity("bot", "proj")
        sig1 = identity.sign(b"hello")
        sig2 = identity.sign(b"world")
        assert sig1 != sig2


class TestRepr:
    def test_repr_contains_fields(self):
        identity = AgentIdentity("research-bot", "phd-lab")
        r = repr(identity)
        assert "research-bot" in r
        assert "phd-lab" in r
        assert "ag:sha256:" in r
