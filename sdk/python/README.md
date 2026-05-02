# agentid — Python SDK

Cryptographic identity for AI agents. Replaces hardcoded API keys with offline-verifiable Ed25519 tokens — verified in **<0.1 ms**, zero network calls.

This is the official Python SDK for [AgentID](https://github.com/samvardhan03/AgentID). It compiles the Rust core via [Maturin](https://www.maturin.rs/) + [PyO3](https://pyo3.rs/) into a native Python extension, so you get Rust-speed crypto with a Pythonic API.

## Installation

```bash
pip install agentid
```

For framework integrations, install with extras:

```bash
pip install agentid[langgraph]    # LangGraph middleware
pip install agentid[crewai]       # CrewAI decorator
pip install agentid[fastapi]      # FastAPI/Starlette middleware
pip install agentid[all]          # Everything
```

## Quick Start

```python
from agentid import AgentIdentity, verify_token

# Derive a deterministic identity — same inputs → same keypair, every time.
identity = AgentIdentity("research-bot", "phd-lab")
print(identity.fingerprint)  # ag:sha256:022a6b57...

# Mint a compact binary token (~173 bytes, not 800 like JWT).
token = identity.mint_token(
    scopes=["read:arxiv", "write:notes"],
    ttl_seconds=900,
    max_calls=100,
)

# Verify offline. No network. No key server. <0.1 ms.
claims = verify_token(token, expected_pubkey=identity.public_key)
print(claims.name)       # research-bot
print(claims.permits("read:arxiv"))  # True
```

## Framework Integrations

### LangGraph

```python
from langgraph.graph import StateGraph
from agentid.middleware.langgraph import agentid_auth_node

graph = StateGraph(dict)
graph.add_node("auth", agentid_auth_node(
    trusted_keys=[identity.public_key],
    required_scopes=["read:arxiv"],
))
graph.add_node("research", research_node)
graph.add_edge("auth", "research")
graph.set_entry_point("auth")
```

### CrewAI

```python
from crewai import Agent
from agentid.middleware.crewai import agentid_authenticate

@agentid_authenticate(
    identity=identity,
    scopes=["read:arxiv", "write:notes"],
)
def create_researcher():
    return Agent(role="Senior Researcher", goal="Find papers", backstory="...")
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from agentid.middleware.fastapi import AgentIDMiddleware, require_scope

app = FastAPI()
app.add_middleware(AgentIDMiddleware, trusted_keys=[identity.public_key])

@app.get("/papers")
async def list_papers(claims=Depends(require_scope("read:arxiv"))):
    return {"agent": claims.name}
```

## Development

```bash
# Install Rust (https://rustup.rs)
# Then:
cd sdk/python
pip install maturin
maturin develop            # Build + install in dev mode
pytest tests/              # Run tests
```

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).
