"""Tests for agentid.middleware — LangGraph, CrewAI, and FastAPI integrations.

These tests exercise the middleware logic using only the agentid core (no actual
LangGraph/CrewAI/FastAPI servers needed).
"""

import pytest
from agentid import AgentIdentity, verify_token
from agentid.integrations.langgraph import agentid_auth_node


# ---------------------------------------------------------------------------
# LangGraph auth node
# ---------------------------------------------------------------------------

class TestLangGraphNode:
    def setup_method(self):
        self.identity = AgentIdentity("research-bot", "phd-lab")
        self.token = self.identity.mint_token(
            scopes=["read:arxiv", "write:notes"],
            ttl_seconds=300,
        )

    def test_valid_token_passes(self):
        node = agentid_auth_node(
            trusted_keys=[self.identity.public_key],
        )
        state = {"agentid_token": self.token}
        result = node(state)
        assert "agentid_claims" in result
        assert result["agentid_claims"].name == "research-bot"

    def test_missing_token_returns_error(self):
        node = agentid_auth_node()
        result = node({})
        assert "agentid_error" in result
        assert "Missing" in result["agentid_error"]

    def test_invalid_token_returns_error(self):
        node = agentid_auth_node()
        result = node({"agentid_token": b"\x00" * 10})
        assert "agentid_error" in result

    def test_scope_enforcement(self):
        node = agentid_auth_node(
            trusted_keys=[self.identity.public_key],
            required_scopes=["delete:everything"],
        )
        result = node({"agentid_token": self.token})
        assert "agentid_error" in result
        assert "delete:everything" in result["agentid_error"]

    def test_scope_passes_when_granted(self):
        node = agentid_auth_node(
            trusted_keys=[self.identity.public_key],
            required_scopes=["read:arxiv"],
        )
        result = node({"agentid_token": self.token})
        assert "agentid_claims" in result

    def test_untrusted_key_returns_error(self):
        other = AgentIdentity("other", "proj")
        node = agentid_auth_node(trusted_keys=[other.public_key])
        result = node({"agentid_token": self.token})
        assert "agentid_error" in result


# ---------------------------------------------------------------------------
# CrewAI decorator (no actual CrewAI dependency needed)
# ---------------------------------------------------------------------------

class TestCrewAIDecorator:
    def test_decorator_attaches_metadata(self):
        from agentid.integrations.crewai import agentid_authenticate

        identity = AgentIdentity("bot", "proj")

        @agentid_authenticate(
            identity=identity,
            scopes=["read:arxiv"],
            ttl_seconds=300,
        )
        def make_agent():
            # Simulate a CrewAI Agent as a simple namespace object.
            class FakeAgent:
                role = "Researcher"
            return FakeAgent()

        agent = make_agent()
        assert hasattr(agent, "_agentid_identity")
        assert hasattr(agent, "_agentid_token")
        assert agent._agentid_identity is identity
        assert isinstance(agent._agentid_token, bytes)

    def test_get_agent_claims(self):
        from agentid.integrations.crewai import agentid_authenticate, get_agent_claims

        identity = AgentIdentity("bot", "proj")

        @agentid_authenticate(identity=identity, scopes=["read:*"], ttl_seconds=300)
        def make_agent():
            class FakeAgent:
                pass
            return FakeAgent()

        agent = make_agent()
        claims = get_agent_claims(agent)
        assert claims is not None
        assert claims.name == "bot"
        assert claims.permits("read:arxiv")

    def test_verify_agent_scope(self):
        from agentid.integrations.crewai import agentid_authenticate, verify_agent_scope

        identity = AgentIdentity("bot", "proj")

        @agentid_authenticate(identity=identity, scopes=["read:arxiv"], ttl_seconds=300)
        def make_agent():
            class FakeAgent:
                pass
            return FakeAgent()

        agent = make_agent()
        assert verify_agent_scope(agent, "read:arxiv") is True
        assert verify_agent_scope(agent, "write:arxiv") is False
