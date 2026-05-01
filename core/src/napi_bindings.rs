//! N-API bindings for Node and Bun.
//!
//! Built when `--features napi-bindings` is enabled. The resulting `cdylib`
//! is renamed to a `.node` file by the SDK build script and loaded directly.
//!
//! All cryptographic types are surfaced as plain JS objects (hex strings for
//! 32-byte keys; `Uint8Array` / `Buffer` for variable-length blobs like
//! tokens). This avoids exposing raw pointer types across the FFI boundary.

#![allow(clippy::needless_pass_by_value)]

use napi_derive::napi;

use crate::identity::{fingerprint_from_pubkey, AgentIdentity};
use crate::token::{parse, verify, AgentClaims, TokenBuilder};
use crate::vault::Vault;
use std::path::PathBuf;

/// Plain-data identity, returned to JS.
#[napi(object)]
pub struct JsIdentity {
    pub name: String,
    pub project: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// `ag:sha256:<16-hex>`.
    pub fingerprint: String,
    /// Hex-encoded 32-byte Ed25519 secret key. Sensitive — caller must wipe.
    pub secret_key: String,
}

/// Plain-data claims, returned to JS.
#[napi(object)]
pub struct JsAgentClaims {
    pub name: String,
    pub project: String,
    pub scopes: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_calls: u32,
    /// Random per-token nonce, as 16 hex chars.
    pub token_id: String,
    /// Hex-encoded 32-byte issuer pubkey.
    pub issuer: String,
    /// `ag:sha256:<16-hex>`.
    pub fingerprint: String,
}

/// Public vault entry, returned to JS.
#[napi(object)]
pub struct JsVaultEntry {
    pub name: String,
    pub project: String,
    pub fingerprint: String,
    pub public_key: String,
    pub created_at: i64,
}

#[napi]
pub fn version() -> String {
    crate::VERSION.to_string()
}

#[napi]
pub fn fingerprint_from_public_key_hex(public_key_hex: String) -> napi::Result<String> {
    let bytes = hex::decode(&public_key_hex)
        .map_err(|_| napi::Error::from_reason("invalid public_key hex"))?;
    if bytes.len() != 32 {
        return Err(napi::Error::from_reason("public_key must be 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(fingerprint_from_pubkey(&a))
}

/// Deterministically derive an identity from `(name, project, seed?)`.
#[napi]
pub fn derive_identity(
    name: String,
    project: String,
    seed: Option<napi::bindgen_prelude::Buffer>,
) -> napi::Result<JsIdentity> {
    let seed_slice = seed.as_ref().map(|b| b.as_ref());
    let id = AgentIdentity::derive(&name, &project, seed_slice)
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(JsIdentity {
        name: id.name.clone(),
        project: id.project.clone(),
        public_key: id.public_key_hex(),
        fingerprint: id.fingerprint(),
        secret_key: hex::encode(id.secret_bytes()),
    })
}

/// Mint a token from a hex-encoded secret key.
#[napi]
pub fn mint_token(
    name: String,
    project: String,
    secret_key_hex: String,
    scopes: Vec<String>,
    ttl_seconds: u32,
    max_calls: u32,
) -> napi::Result<napi::bindgen_prelude::Buffer> {
    let secret = hex::decode(&secret_key_hex)
        .map_err(|_| napi::Error::from_reason("invalid secret_key hex"))?;
    let id = AgentIdentity::from_secret_bytes(&name, &project, &secret)
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    let token = TokenBuilder::new(&id)
        .scopes(scopes)
        .ttl_seconds(ttl_seconds as u64)
        .max_calls(max_calls)
        .build()
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(token.into())
}

/// Parse a token without verifying its signature or expiry. Debug only.
#[napi]
pub fn parse_token(token: napi::bindgen_prelude::Buffer) -> napi::Result<JsAgentClaims> {
    let claims = parse(token.as_ref()).map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(claims_to_js(&claims))
}

/// Parse + cryptographically verify a token. If `expected_pubkey_hex` is
/// provided, the token's issuer must match.
#[napi]
pub fn verify_token(
    token: napi::bindgen_prelude::Buffer,
    expected_pubkey_hex: Option<String>,
) -> napi::Result<JsAgentClaims> {
    let expected = match expected_pubkey_hex {
        Some(h) => {
            let v = hex::decode(&h)
                .map_err(|_| napi::Error::from_reason("invalid expected_pubkey hex"))?;
            if v.len() != 32 {
                return Err(napi::Error::from_reason("expected_pubkey must be 32 bytes"));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Some(a)
        }
        None => None,
    };
    let claims =
        verify(token.as_ref(), expected.as_ref()).map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(claims_to_js(&claims))
}

#[napi]
pub fn vault_default_root() -> napi::Result<String> {
    Vault::default_root()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| napi::Error::from_reason(format!("{e}")))
}

#[napi]
pub fn vault_init(root: String) -> napi::Result<()> {
    Vault::new(PathBuf::from(root))
        .init()
        .map_err(|e| napi::Error::from_reason(format!("{e}")))
}

#[napi]
pub fn vault_list(root: String) -> napi::Result<Vec<JsVaultEntry>> {
    let v = Vault::new(PathBuf::from(root));
    let entries = v.list().map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(entries
        .into_iter()
        .map(|e| JsVaultEntry {
            name: e.name,
            project: e.project,
            fingerprint: e.fingerprint,
            public_key: e.public_key,
            created_at: e.created_at,
        })
        .collect())
}

#[napi]
pub fn vault_store(
    root: String,
    name: String,
    project: String,
    seed_hex: Option<String>,
    password: String,
) -> napi::Result<JsVaultEntry> {
    let seed_bytes = match seed_hex {
        Some(h) if !h.is_empty() => Some(
            hex::decode(&h).map_err(|_| napi::Error::from_reason("invalid seed hex"))?,
        ),
        _ => None,
    };
    let id = AgentIdentity::derive(&name, &project, seed_bytes.as_deref())
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    let v = Vault::new(PathBuf::from(root));
    let entry = v
        .store(&id, &password)
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(JsVaultEntry {
        name: entry.name,
        project: entry.project,
        fingerprint: entry.fingerprint,
        public_key: entry.public_key,
        created_at: entry.created_at,
    })
}

#[napi]
pub fn vault_load_secret_hex(
    root: String,
    fingerprint: String,
    password: String,
) -> napi::Result<JsIdentity> {
    let v = Vault::new(PathBuf::from(root));
    let id = v
        .load(&fingerprint, &password)
        .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
    Ok(JsIdentity {
        name: id.name.clone(),
        project: id.project.clone(),
        public_key: id.public_key_hex(),
        fingerprint: id.fingerprint(),
        secret_key: hex::encode(id.secret_bytes()),
    })
}

#[napi]
pub fn vault_remove(root: String, fingerprint: String) -> napi::Result<()> {
    Vault::new(PathBuf::from(root))
        .remove(&fingerprint)
        .map_err(|e| napi::Error::from_reason(format!("{e}")))
}

fn claims_to_js(c: &AgentClaims) -> JsAgentClaims {
    JsAgentClaims {
        name: c.name.clone(),
        project: c.project.clone(),
        scopes: c.scopes.clone(),
        issued_at: c.issued_at,
        expires_at: c.expires_at,
        max_calls: c.max_calls,
        token_id: format!("{:016x}", c.token_id),
        issuer: hex::encode(c.issuer),
        fingerprint: c.fingerprint(),
    }
}
