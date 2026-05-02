"""
E2E test client — sends actual HTTP requests to the FastAPI server.

Tests:
  1. Public endpoint (no token)         -> 200
  2. Protected endpoint (no token)      -> 401
  3. Protected endpoint (garbage token)  -> 401
  4. Protected endpoint (valid token, right scope)  -> 200
  5. Admin endpoint (valid token, wrong scope)      -> 403
  6. Protected endpoint (wrong identity's token)    -> 401
"""
import binascii
import httpx
from agentid import AgentIdentity

BASE = "http://127.0.0.1:8000"

# Same identity as the server trusts
chaos = AgentIdentity("chaos-monkey", "test-xyz")

# A different identity the server does NOT trust
intruder = AgentIdentity("evil-bot", "hacker-proj")


def mint_header(identity, scopes, ttl=60, max_calls=0):
    """Mint a token and return it as an Authorization header."""
    token = identity.mint_token(scopes=scopes, ttl_seconds=ttl, max_calls=max_calls)
    return {"Authorization": f"AgentID {binascii.hexlify(token).decode()}"}


def test(name, method, url, headers=None, expect_status=200):
    """Send a request and check the status code."""
    fn = getattr(httpx, method)
    r = fn(url, headers=headers or {})
    status = "PASS" if r.status_code == expect_status else "FAIL"
    print(f"[{status}] {name}")
    print(f"       {method.upper()} {url}")
    print(f"       Expected: {expect_status}  Got: {r.status_code}")
    body = r.json()
    for k, v in body.items():
        print(f"       {k}: {v}")
    print()
    if r.status_code != expect_status:
        raise AssertionError(f"{name}: expected {expect_status}, got {r.status_code}")
    return body


print("=" * 60)
print("AgentID FastAPI E2E Test")
print("=" * 60)
print()

# 1. Public endpoint — no token needed
test("Public endpoint (no token)", "get", f"{BASE}/public", expect_status=200)

# 2. Protected endpoint — no token -> 401
test("Protected (no token)", "get", f"{BASE}/protected", expect_status=401)

# 3. Protected endpoint — garbage token -> 401
test("Protected (garbage token)", "get", f"{BASE}/protected",
     headers={"Authorization": "AgentID deadbeef00"},
     expect_status=401)

# 4. Protected endpoint — valid token with read:data scope -> 200
headers = mint_header(chaos, scopes=["read:data", "write:notes"])
body = test("Protected (valid token, read:data)", "get", f"{BASE}/protected",
            headers=headers, expect_status=200)
assert body["agent"] == "chaos-monkey"
assert body["project"] == "test-xyz"
assert "read:data" in body["scopes"]

# 5. Admin endpoint — valid token but NO admin scope -> 403
headers = mint_header(chaos, scopes=["read:data"])
test("Admin (valid token, wrong scope)", "post", f"{BASE}/admin",
     headers=headers, expect_status=403)

# 6. Protected endpoint — intruder's token (untrusted key) -> 401
headers = mint_header(intruder, scopes=["read:data"])
test("Protected (intruder's token)", "get", f"{BASE}/protected",
     headers=headers, expect_status=401)

print("=" * 60)
print("ALL E2E TESTS PASSED")
print("=" * 60)
