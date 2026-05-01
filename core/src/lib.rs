//! # agentid-core
//!
//! Cryptographic identity for AI agents.
//!
//! Provides:
//!  * Deterministic Ed25519 keypair generation from `(name, project, seed?)`.
//!  * A compact binary token format (~180 bytes) embedding scopes, TTL, and
//!    a per-token call quota — verifiable offline in <0.1 ms.
//!  * An encrypted local key vault (AES-256-GCM, PBKDF2-HMAC-SHA256).
//!  * An optional gRPC server (feature `server`).
//!  * Optional N-API bindings for Node/Bun (feature `napi-bindings`).
//!
//! ## Why a custom binary format?
//!
//! JWTs were designed for human-mediated web sessions. They carry JSON
//! headers, base64 payloads, RSA/ECDSA signatures, and JWK discovery overhead
//! — none of which benefit machine-to-machine agent traffic. AgentID tokens
//! are binary, Ed25519, and self-contained, with rate limits embedded in the
//! signed payload itself.

pub mod identity;
pub mod scopes;
pub mod token;
pub mod vault;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "napi-bindings")]
mod napi_bindings;

pub use identity::{verify_signature, AgentIdentity, IdentityError};
pub use scopes::{Scope, ScopeError};
pub use token::{
    parse as parse_token, verify as verify_token, AgentClaims, TokenBuilder, TokenError,
};
pub use vault::{Vault, VaultEntry, VaultError, VaultIndex};

/// Library version, from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
