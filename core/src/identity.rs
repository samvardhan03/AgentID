//! Agent identity — Ed25519 keypair derivation and signing primitives.
//!
//! Identities are deterministic by default: given the same
//! `(name, project, seed?)` triple, the same secret key is produced. This is
//! intentional — it lets a developer recreate an identity on a new machine
//! from the same inputs without copying secret material around. For one-off
//! ephemeral identities, callers can pass a random seed.
//!
//! Derivation:
//!
//! ```text
//!   IKM   = name || 0x00 || project || 0x00 || seed?
//!   salt  = b"agentid-v1"
//!   info  = b"ed25519-signing-key"
//!   okm   = HKDF-SHA256(salt, IKM, info, len = 32)
//!   sk    = Ed25519 SigningKey::from_bytes(okm)
//! ```

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const HKDF_SALT: &[u8] = b"agentid-v1";
const HKDF_INFO: &[u8] = b"ed25519-signing-key";

/// Errors produced by the identity layer.
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("invalid public key length: expected 32, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid secret key length: expected 32, got {0}")]
    InvalidSecretKeyLength(usize),
    #[error("invalid signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("name must not be empty")]
    EmptyName,
    #[error("project must not be empty")]
    EmptyProject,
    #[error("name too long: max 255 bytes, got {0}")]
    NameTooLong(usize),
    #[error("project too long: max 255 bytes, got {0}")]
    ProjectTooLong(usize),
}

/// A cryptographic agent identity. Wraps an Ed25519 [`SigningKey`] alongside
/// the human-readable `(name, project)` tuple that derives it.
pub struct AgentIdentity {
    pub name: String,
    pub project: String,
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Deterministically derive an identity from `(name, project, seed?)`.
    ///
    /// The same inputs always produce the same keypair. Pass a random `seed`
    /// to mint an ephemeral identity that's still bound to a name/project for
    /// logging.
    pub fn derive(name: &str, project: &str, seed: Option<&[u8]>) -> Result<Self, IdentityError> {
        validate_name_project(name, project)?;

        let mut ikm = Vec::with_capacity(name.len() + project.len() + 2 + seed.map_or(0, <[u8]>::len));
        ikm.extend_from_slice(name.as_bytes());
        ikm.push(0);
        ikm.extend_from_slice(project.as_bytes());
        ikm.push(0);
        if let Some(s) = seed {
            ikm.extend_from_slice(s);
        }

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
        let mut okm = [0u8; SECRET_KEY_LENGTH];
        hk.expand(HKDF_INFO, &mut okm)
            .expect("HKDF-SHA256 expand to 32 bytes never fails");
        let signing_key = SigningKey::from_bytes(&okm);

        ikm.zeroize();
        okm.zeroize();

        Ok(Self {
            name: name.to_string(),
            project: project.to_string(),
            signing_key,
        })
    }

    /// Reconstruct an identity from a raw 32-byte Ed25519 secret key.
    pub fn from_secret_bytes(
        name: &str,
        project: &str,
        secret: &[u8],
    ) -> Result<Self, IdentityError> {
        validate_name_project(name, project)?;
        if secret.len() != SECRET_KEY_LENGTH {
            return Err(IdentityError::InvalidSecretKeyLength(secret.len()));
        }
        let mut sk = [0u8; SECRET_KEY_LENGTH];
        sk.copy_from_slice(secret);
        let signing_key = SigningKey::from_bytes(&sk);
        sk.zeroize();
        Ok(Self {
            name: name.to_string(),
            project: project.to_string(),
            signing_key,
        })
    }

    /// 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Hex-encoded public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// 32-byte Ed25519 secret key. Treat as sensitive — caller is responsible
    /// for zeroising the returned buffer.
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Underlying signing key, for advanced uses.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Human-readable fingerprint: `ag:sha256:<first-16-hex-chars-of-SHA256(pubkey)>`.
    pub fn fingerprint(&self) -> String {
        fingerprint_from_pubkey(&self.public_key())
    }

    /// Sign an arbitrary message with this identity.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("name", &self.name)
            .field("project", &self.project)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// Verify an Ed25519 signature.
pub fn verify_signature(
    public_key: &[u8; 32],
    msg: &[u8],
    signature: &[u8; SIGNATURE_LENGTH],
) -> Result<(), IdentityError> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(msg, &sig).map_err(|_| IdentityError::BadSignature)
}

/// Compute the fingerprint string from a raw public key.
pub fn fingerprint_from_pubkey(pubkey: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(pubkey);
    let digest = h.finalize();
    format!("ag:sha256:{}", &hex::encode(digest)[..16])
}

fn validate_name_project(name: &str, project: &str) -> Result<(), IdentityError> {
    if name.is_empty() {
        return Err(IdentityError::EmptyName);
    }
    if project.is_empty() {
        return Err(IdentityError::EmptyProject);
    }
    if name.len() > 255 {
        return Err(IdentityError::NameTooLong(name.len()));
    }
    if project.len() > 255 {
        return Err(IdentityError::ProjectTooLong(project.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = AgentIdentity::derive("research-bot", "phd-lab", None).unwrap();
        let b = AgentIdentity::derive("research-bot", "phd-lab", None).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn different_projects_produce_different_keys() {
        let a = AgentIdentity::derive("bot", "proj-a", None).unwrap();
        let b = AgentIdentity::derive("bot", "proj-b", None).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn seed_changes_key() {
        let a = AgentIdentity::derive("bot", "proj", None).unwrap();
        let b = AgentIdentity::derive("bot", "proj", Some(b"extra")).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn round_trip_secret_bytes() {
        let a = AgentIdentity::derive("bot", "proj", None).unwrap();
        let bytes = a.secret_bytes();
        let b = AgentIdentity::from_secret_bytes("bot", "proj", &bytes).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn sign_and_verify() {
        let a = AgentIdentity::derive("bot", "proj", None).unwrap();
        let msg = b"hello";
        let sig = a.sign(msg);
        let pk = a.public_key();
        assert!(verify_signature(&pk, msg, &sig.to_bytes()).is_ok());
        assert!(verify_signature(&pk, b"goodbye", &sig.to_bytes()).is_err());
    }

    #[test]
    fn fingerprint_format() {
        let a = AgentIdentity::derive("bot", "proj", None).unwrap();
        let fp = a.fingerprint();
        assert!(fp.starts_with("ag:sha256:"));
        assert_eq!(fp.len(), "ag:sha256:".len() + 16);
    }

    #[test]
    fn rejects_empty_name() {
        assert!(matches!(
            AgentIdentity::derive("", "proj", None),
            Err(IdentityError::EmptyName)
        ));
    }
}
