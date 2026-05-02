# AgentID

**Every AI agent in production today authenticates with hardcoded API keys. That's the equivalent of shipping a web app with `password: admin`. AgentID fixes this.**

AgentID gives every AI agent a cryptographic identity — an Ed25519 keypair that acts as the agent's passport. Any service can verify *"this request came from agent X, with scopes Y, and has not been tampered with"* in **under 0.1 ms**, with zero network calls, zero key servers, zero JWT libraries.

```
cargo add agentid-core
```

---

## Why not JWTs?

JWT was designed for human browser sessions. For machine-to-machine agent traffic, it's the wrong tool:

| | **JWT (RS256)** | **AgentID Token** |
|---|---|---|
| **Size** | ~800 bytes | **~173 bytes** |
| **Verification** | ~0.4 ms (RSA) | **<0.1 ms (Ed25519)** |
| **Rate limits** | ❌ Not in spec | ✅ Baked into the signed payload |
| **Scopes** | String claim (not enforced) | ✅ Cryptographically bound |
| **Key discovery** | JWK endpoint required | ✅ Offline, no network |
| **Agent-native** | ❌ | ✅ |

The AgentID binary wire format (`0xA9 0x1D` magic) packs a complete token — issuer pubkey, scopes, TTL, call quota, and Ed25519 signature — into 173 bytes. Deserialisation and signature verification complete in a single cache-hot pass.

---

## Quick Start

### Rust

```rust
use agentid_core::{AgentIdentity, TokenBuilder, verify_token};

// Derive a deterministic identity from name + project.
// Same inputs → same keypair, every time, on every machine.
let identity = AgentIdentity::derive("research-bot", "phd-lab", None)?;

println!("public key : {}", identity.public_key_hex());
println!("fingerprint: {}", identity.fingerprint()); // ag:sha256:022a6b57...

// Mint a compact binary token — 173 bytes, not 800.
let token = TokenBuilder::new(&identity)
    .scopes(["read:arxiv", "write:notes"])
    .ttl_seconds(900)
    .max_calls(100)
    .build()?;

// Verify offline. No network. No key server. <0.1 ms.
let claims = verify_token(&token, Some(&identity.public_key()))?;

assert_eq!(claims.name, "research-bot");
assert!(claims.permits("read:arxiv")); // wildcard scope matching
```

### CLI

```bash
# Initialise the local vault
agentid init

# Store an identity (encrypted with AES-256-GCM, password-derived via PBKDF2)
agentid keys add --name research-bot --project phd-lab

# Mint a token
agentid mint --name research-bot --project phd-lab \
  --scopes "read:arxiv,write:notes" --ttl 900 --max-calls 100

# Verify
agentid verify <token>
# Token verified.
#   name         research-bot
#   project      phd-lab
#   fingerprint  ag:sha256:022a6b577d76ae03
#   scopes       read:arxiv, write:notes
#   expires      2026-05-02T10:14:51.000Z
#   max_calls    100

# Start the optional gRPC server for centralised key management
agentid serve --port 6100
```

### TypeScript / Bun

```typescript
import { AgentIdentity, verifyToken, vault } from "agentid";

// Derive an identity
const id = AgentIdentity.derive("research-bot", "phd-lab");

// Mint
const token = id.mintToken({ scopes: ["read:arxiv"], ttlSeconds: 900 });

// Verify
const claims = verifyToken(token, id.publicKey);
console.log(claims.fingerprint); // ag:sha256:022a6b577d76ae03
```

---

## Architecture

### Token Wire Format

```
off  size  field
---  ----  -----
  0     2  magic          0xA9 0x1D
  2     1  version        0x01
  3     1  flags          0x00 (reserved)
  4     8  issued_at      i64 BE (unix seconds)
 12     8  expires_at     i64 BE
 20     4  max_calls      u32 BE  (0 = unlimited)
 24     8  token_id       u64 BE  (random nonce, replay protection)
 32    32  issuer_pubkey  Ed25519 (32 bytes)
 64   var  name, project, scopes  (u8 length-prefixed utf-8)
END    64  Ed25519 signature over bytes [0..END)
```

Every field is inside the signed region. A single byte flip anywhere causes verification to fail.

### Deterministic Key Derivation

```
IKM   = name ‖ 0x00 ‖ project ‖ 0x00 ‖ seed?
salt  = b"agentid-v1"
info  = b"ed25519-signing-key"
okm   = HKDF-SHA256(salt, IKM, info, len=32)
sk    = Ed25519 SigningKey::from_bytes(okm)
```

The same `(name, project)` pair always produces the same keypair — reproducible across machines, no secret material to copy around.

### Local Vault

Secret keys at `~/.agentid/keys/<fingerprint>.key`:

- **KDF:** PBKDF2-HMAC-SHA256, 200 000 iterations
- **Cipher:** AES-256-GCM (nonce + tag per file)
- **Permissions:** `0o600` (user-only)
- **Index:** Unencrypted `~/.agentid/index.json` (public metadata only — safe to back up)

### Scope Matching

```
"read:arxiv"  →  matches exactly "read:arxiv"
"read:*"      →  matches "read:arxiv", "read:notes", ...
"*"           →  matches any scope
"*:papers"    →  matches "read:papers", "write:papers"
```

---

## Feature Flags

| Flag | What it adds |
|---|---|
| `server` *(default)* | Tonic gRPC server — `agentid serve --port 6100` |
| `napi-bindings` | N-API cdylib for Node / Bun TypeScript SDK |

```toml
# Core library only (no async runtime)
agentid-core = { version = "0.1", default-features = false }

# Default: core + gRPC server
agentid-core = "0.1"
```

---

## Roadmap

- **v0.1** — Ed25519 identity, binary tokens, AES-256-GCM vault, gRPC server, TypeScript SDK, Bun CLI ✅
- **v0.2** — LangGraph + CrewAI framework middleware, token revocation list, key rotation
- **v0.3** — AgentID Cloud (hosted key management, audit log, team dashboard)

---

## License

Apache License 2.0 — free for open-source and commercial use **with attribution**.

> When using AgentID in a public project or product, you must give clear credit to the original author, **Samvardhan Singh**, in your documentation, `README`, or `NOTICE` file.

For enterprise use requiring white-labelling or a no-attribution obligation, contact the author for a commercial licence.

See [`LICENSE`](LICENSE) for the full text.

---

*Three tools. Four launches. One platform. Ship the knife before you sell the kitchen.*
