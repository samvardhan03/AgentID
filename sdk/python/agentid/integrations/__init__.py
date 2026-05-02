"""
agentid.integrations — Framework integrations for LangGraph, CrewAI, and FastAPI.
"""

from agentid.integrations.fastapi import (
    AgentIDMiddleware,
    require_agent_auth,
    require_scope,
    VerifiedAgent,
)
from agentid.integrations.langgraph import AgentIDLangGraphMiddleware, agentid_auth_node
from agentid.integrations.crewai import AgentIDCrewMixin, agentid_authenticate

__all__ = [
    # Blueprint-specified names
    "AgentIDMiddleware",
    "AgentIDLangGraphMiddleware",
    "AgentIDCrewMixin",
    "require_agent_auth",
    "VerifiedAgent",
    # Our additional APIs
    "require_scope",
    "agentid_auth_node",
    "agentid_authenticate",
]
