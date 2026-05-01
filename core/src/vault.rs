//! Encrypted on-disk key vault.
//!
//! Layout:
//!
//! ```text
//!   ~/.agentid/
//!     index.json                              # public metadata only
//!     keys/<sanitised-fingerprint>.key        # AES-256-GCM ciphertext
//! ```
//!
//! ## Per-key file format
//!
//! ```text
//!   off   size   field
//!   ---   ----   -----
//!     0      4   magic           = 0xA9 0x1D 0x56 0x01
//!     4      1   version         = 0x01
//!     5     16   pbkdf2 salt
//!    21     12   gcm nonce
//!    33      4   pbkdf2 iters    (u32 BE)
//!    37    var   ciphertext || gcm tag
//! ```
//!
//! * KDF: PBKDF2-HMAC-SHA256, default 200 000 iterations.
//! * Cipher: AES-256-GCM (no AAD — file format is implicit context).
//! * Plaintext: JSON-encoded [`StoredKey`] (`name + project + secret_hex`).
//!
//! Files are written with `0o600`; the `~/.agentid` directory with `0o700`.

use crate::identity::{AgentIdentity, IdentityError};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroize;

const VAULT_MAGIC: [u8; 4] = [0xA9, 0x1D, 0x56, 0x01];
const VAULT_VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + 4;
const DEFAULT_PBKDF2_ITERS: u32 = 200_000;
const MIN_PBKDF2_ITERS: u32 = 50_000;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid vault file magic")]
    InvalidMagic,
    #[error("unsupported vault file version: {0:#x}")]
    UnsupportedVersion(u8),
    #[error("pbkdf2 iterations too low: {got} (min {min})", min = MIN_PBKDF2_ITERS)]
    IterationsTooLow { got: u32 },
    #[error("malformed vault file: {0}")]
    Malformed(&'static str),
    #[error("decryption failed (wrong password?)")]
    DecryptionFailed,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("vault not initialized at {0}")]
    NotInitialized(PathBuf),
    #[error("identity already exists: {0}")]
    AlreadyExists(String),
    #[error("identity not found: {0}")]
    NotFound(String),
    #[error("home directory not found")]
    NoHome,
}

/// Public metadata for a vault entry. Safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub name: String,
    pub project: String,
    pub fingerprint: String,
    pub public_key: String, // hex
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultIndex {
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<VaultEntry>,
}

impl Default for VaultIndex {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// Plaintext payload encrypted in each key file. Held in memory only briefly.
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct StoredKey {
    name: String,
    project: String,
    /// Hex-encoded 32-byte Ed25519 secret key.
    secret_hex: String,
    created_at: i64,
}

/// Vault rooted at a directory (typically `~/.agentid`).
pub struct Vault {
    root: PathBuf,
}

impl Vault {
    /// Default vault root: `$HOME/.agentid`.
    pub fn default_root() -> Result<PathBuf, VaultError> {
        Ok(dirs::home_dir().ok_or(VaultError::NoHome)?.join(".agentid"))
    }

    /// Open a vault at the given root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    /// Initialise the vault directory tree and a fresh empty index.
    pub fn init(&self) -> Result<(), VaultError> {
        fs::create_dir_all(self.keys_dir())?;
        if !self.index_path().exists() {
            self.write_index(&VaultIndex::default())?;
        }
        set_dir_perms(&self.root)?;
        set_dir_perms(&self.keys_dir())?;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.index_path().exists()
    }

    /// Read the public index. Returns [`VaultError::NotInitialized`] if the
    /// vault has never been `init`'d.
    pub fn read_index(&self) -> Result<VaultIndex, VaultError> {
        if !self.index_path().exists() {
            return Err(VaultError::NotInitialized(self.root.clone()));
        }
        let bytes = fs::read(self.index_path())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_index(&self, idx: &VaultIndex) -> Result<(), VaultError> {
        let s = serde_json::to_string_pretty(idx)?;
        fs::write(self.index_path(), s)?;
        set_file_perms(&self.index_path())?;
        Ok(())
    }

    /// Public view of all stored identities.
    pub fn list(&self) -> Result<Vec<VaultEntry>, VaultError> {
        Ok(self.read_index()?.entries)
    }

    /// Persist an identity under `password`.
    pub fn store(&self, identity: &AgentIdentity, password: &str) -> Result<VaultEntry, VaultError> {
        let mut idx = self.read_index()?;
        let fingerprint = identity.fingerprint();
        if idx.entries.iter().any(|e| e.fingerprint == fingerprint) {
            return Err(VaultError::AlreadyExists(fingerprint));
        }
        let entry = VaultEntry {
            name: identity.name.clone(),
            project: identity.project.clone(),
            fingerprint: fingerprint.clone(),
            public_key: identity.public_key_hex(),
            created_at: now_secs(),
        };
        let mut secret = identity.secret_bytes();
        let stored = StoredKey {
            name: identity.name.clone(),
            project: identity.project.clone(),
            secret_hex: hex::encode(secret),
            created_at: entry.created_at,
        };
        secret.zeroize();
        let plaintext = serde_json::to_vec(&stored)?;
        let key_path = self.key_file_path(&fingerprint);
        encrypt_to_file(&key_path, &plaintext, password)?;
        // plaintext is now safe to drop; serde_json::to_vec returned a fresh Vec
        drop(plaintext);

        idx.entries.push(entry.clone());
        self.write_index(&idx)?;
        Ok(entry)
    }

    /// Decrypt and load an identity by fingerprint.
    pub fn load(&self, fingerprint: &str, password: &str) -> Result<AgentIdentity, VaultError> {
        let key_path = self.key_file_path(fingerprint);
        if !key_path.exists() {
            return Err(VaultError::NotFound(fingerprint.to_string()));
        }
        let mut plaintext = decrypt_from_file(&key_path, password)?;
        let stored: StoredKey = serde_json::from_slice(&plaintext)?;
        plaintext.zeroize();
        let mut secret = hex::decode(&stored.secret_hex)
            .map_err(|_| VaultError::Malformed("invalid secret_hex"))?;
        let identity = AgentIdentity::from_secret_bytes(&stored.name, &stored.project, &secret)?;
        secret.zeroize();
        Ok(identity)
    }

    /// Resolve a fingerprint by `name@project`. Convenience for the CLI.
    pub fn lookup_by_name_project(
        &self,
        name: &str,
        project: &str,
    ) -> Result<VaultEntry, VaultError> {
        let idx = self.read_index()?;
        idx.entries
            .into_iter()
            .find(|e| e.name == name && e.project == project)
            .ok_or_else(|| VaultError::NotFound(format!("{name}@{project}")))
    }

    pub fn remove(&self, fingerprint: &str) -> Result<(), VaultError> {
        let mut idx = self.read_index()?;
        let before = idx.entries.len();
        idx.entries.retain(|e| e.fingerprint != fingerprint);
        if idx.entries.len() == before {
            return Err(VaultError::NotFound(fingerprint.to_string()));
        }
        let key_path = self.key_file_path(fingerprint);
        if key_path.exists() {
            fs::remove_file(key_path)?;
        }
        self.write_index(&idx)?;
        Ok(())
    }

    fn key_file_path(&self, fingerprint: &str) -> PathBuf {
        // Replace ':' for filesystems that disallow it (Windows). The
        // fingerprint shape is always `ag:sha256:<16-hex>`.
        let safe = fingerprint.replace(':', "_");
        self.keys_dir().join(format!("{safe}.key"))
    }
}

// ---- file encryption ----

fn encrypt_to_file(path: &Path, plaintext: &[u8], password: &str) -> Result<(), VaultError> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).expect("rng");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).expect("rng");

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(DEFAULT_PBKDF2_ITERS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| VaultError::Malformed("aead key construction failed"))?;
    let sealing = LessSafeKey::new(unbound);
    let mut buf = plaintext.to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| VaultError::Malformed("aead seal failed"))?;
    key.zeroize();

    let mut file = fs::File::create(path)?;
    file.write_all(&VAULT_MAGIC)?;
    file.write_all(&[VAULT_VERSION])?;
    file.write_all(&salt)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&DEFAULT_PBKDF2_ITERS.to_be_bytes())?;
    file.write_all(&buf)?;
    file.flush()?;
    set_file_perms(path)?;
    Ok(())
}

fn decrypt_from_file(path: &Path, password: &str) -> Result<Vec<u8>, VaultError> {
    let mut file = fs::File::open(path)?;
    let mut all = Vec::new();
    file.read_to_end(&mut all)?;
    if all.len() < HEADER_LEN + 16 {
        return Err(VaultError::Malformed("vault file shorter than header+tag"));
    }
    if all[0..4] != VAULT_MAGIC {
        return Err(VaultError::InvalidMagic);
    }
    if all[4] != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(all[4]));
    }
    let mut o = 5usize;
    let salt = &all[o..o + SALT_LEN];
    o += SALT_LEN;
    let nonce_bytes: [u8; NONCE_LEN] = all[o..o + NONCE_LEN].try_into().unwrap();
    o += NONCE_LEN;
    let iters = u32::from_be_bytes(all[o..o + 4].try_into().unwrap());
    o += 4;
    if iters < MIN_PBKDF2_ITERS {
        return Err(VaultError::IterationsTooLow { got: iters });
    }
    let mut ciphertext = all[o..].to_vec();

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iters).ok_or(VaultError::Malformed("zero iters"))?,
        salt,
        password.as_bytes(),
        &mut key,
    );
    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| VaultError::Malformed("aead key construction failed"))?;
    let opening = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;
    let result = plaintext.to_vec();
    key.zeroize();
    Ok(result)
}

fn set_dir_perms(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    let _ = path;
    Ok(())
}

fn set_file_perms(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let _ = path;
    Ok(())
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_root() -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        p.push(format!("agentid-vault-test-{pid}-{n}"));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn init_creates_index() {
        let root = temp_root();
        let v = Vault::new(&root);
        v.init().unwrap();
        assert!(v.is_initialized());
        assert!(v.read_index().unwrap().entries.is_empty());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn store_and_load_round_trip() {
        let root = temp_root();
        let v = Vault::new(&root);
        v.init().unwrap();
        let id = AgentIdentity::derive("bot", "proj", None).unwrap();
        let entry = v.store(&id, "correct horse battery staple").unwrap();
        assert_eq!(entry.fingerprint, id.fingerprint());

        let loaded = v.load(&id.fingerprint(), "correct horse battery staple").unwrap();
        assert_eq!(loaded.public_key(), id.public_key());
        assert_eq!(loaded.name, "bot");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn wrong_password_fails() {
        let root = temp_root();
        let v = Vault::new(&root);
        v.init().unwrap();
        let id = AgentIdentity::derive("bot", "proj", None).unwrap();
        v.store(&id, "right").unwrap();
        assert!(matches!(
            v.load(&id.fingerprint(), "wrong"),
            Err(VaultError::DecryptionFailed)
        ));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn duplicate_store_rejected() {
        let root = temp_root();
        let v = Vault::new(&root);
        v.init().unwrap();
        let id = AgentIdentity::derive("bot", "proj", None).unwrap();
        v.store(&id, "pw").unwrap();
        assert!(matches!(v.store(&id, "pw"), Err(VaultError::AlreadyExists(_))));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn remove_works() {
        let root = temp_root();
        let v = Vault::new(&root);
        v.init().unwrap();
        let id = AgentIdentity::derive("bot", "proj", None).unwrap();
        v.store(&id, "pw").unwrap();
        v.remove(&id.fingerprint()).unwrap();
        assert!(v.list().unwrap().is_empty());
        fs::remove_dir_all(&root).ok();
    }
}
