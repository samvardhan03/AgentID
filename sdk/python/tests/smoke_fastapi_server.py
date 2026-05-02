"""
Dummy FastAPI server for end-to-end AgentID testing.

Endpoints:
  GET  /public        — no auth required
  GET  /protected     — requires valid AgentID token
  GET  /scoped        — requires "read:data" scope
  POST /admin         — requires "admin:*" scope
"""
from fastapi import FastAPI, Depends
from agentid import AgentIdentity
from agentid.integrations.fastapi import AgentIDMiddleware, require_agent_auth

# Server-side identity (the "trusted" key)
SERVER_IDENTITY = AgentIdentity("chaos-monkey", "test-xyz")

app = FastAPI(title="AgentID E2E Test Server")

# Add the middleware — it reads Authorization: AgentID <hex-token>
app.add_middleware(
    AgentIDMiddleware,
    trusted_keys=[SERVER_IDENTITY.public_key],
)


@app.get("/public")
async def public_endpoint():
    """No auth needed."""
    return {"status": "ok", "message": "This is public"}


@app.get("/protected")
async def protected_endpoint(claims=Depends(require_agent_auth("read:data"))):
    """Requires a valid token with read:data scope."""
    return {
        "status": "ok",
        "agent": claims.name,
        "project": claims.project,
        "scopes": claims.scopes,
        "fingerprint": claims.fingerprint,
    }


@app.post("/admin")
async def admin_endpoint(claims=Depends(require_agent_auth("admin:*"))):
    """Requires admin:* scope — should be rejected by a read-only token."""
    return {"status": "ok", "admin": True}
