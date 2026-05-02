"""Identity uniqueness + cross-identity rejection test."""
from agentid import AgentIdentity, verify_token

# A completely random identity that's NOT in the README
chaos = AgentIdentity("chaos-monkey", "test-xyz")
readme = AgentIdentity("research-bot", "phd-lab")

print("=== CHAOS MONKEY IDENTITY ===")
print(f"  Name:        {chaos.name}")
print(f"  Project:     {chaos.project}")
print(f"  Fingerprint: {chaos.fingerprint}")
print(f"  PubKey Hex:  {chaos.public_key_hex}")
print()
print("=== README IDENTITY ===")
print(f"  Fingerprint: {readme.fingerprint}")
print()

# PROVE they're different
assert chaos.fingerprint != readme.fingerprint, "FAIL: same fingerprint!"
assert chaos.public_key != readme.public_key, "FAIL: same pubkey!"
print("[PASS] Fingerprints are unique - not hardcoded")

# Mint + verify with chaos monkey
token = chaos.mint_token(scopes=["destroy:everything"], ttl_seconds=60, max_calls=5)
claims = verify_token(token, chaos.public_key)
print("[PASS] Token verified for chaos-monkey")
print(f"  Scopes:    {claims.scopes}")
print(f"  Max calls: {claims.max_calls}")
permits_destroy = claims.permits("destroy:everything")
permits_read = claims.permits("read:arxiv")
print(f"  Permits destroy:everything? {permits_destroy}")
print(f"  Permits read:arxiv?         {permits_read}")
assert permits_destroy is True
assert permits_read is False
print("[PASS] Scope enforcement works correctly")

# Cross-identity rejection: chaos monkey token should FAIL with readme pubkey
try:
    verify_token(token, readme.public_key)
    print("[FAIL] Should have rejected cross-identity token!")
    exit(1)
except RuntimeError as e:
    print("[PASS] Cross-identity rejection works: issuer mismatch detected")

# Determinism: same inputs = same key
chaos2 = AgentIdentity("chaos-monkey", "test-xyz")
assert chaos.public_key == chaos2.public_key
print("[PASS] Deterministic: same inputs = same key")

print()
print("ALL IDENTITY TESTS PASSED")
