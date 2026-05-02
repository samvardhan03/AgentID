//! PyO3 bindings for `agentid-core`.
//!
//! This crate compiles the Rust core into a native Python extension module
//! via Maturin. The resulting `.pyd`/`.so` is imported as `agentid._native`
//! and re-exported through the pure-Python `agentid` package.

use agentid_core::identity::AgentIdentity as RustIdentity;
use agentid_core::token::{
    verify as rust_verify, AgentClaims as RustClaims, TokenBuilder as RustTokenBuilder,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

/// Python-visible `AgentIdentity`.
///
/// Wraps the Rust `AgentIdentity` and exposes key derivation, signing, and
/// token minting to Python callers.
#[pyclass(name = "AgentIdentity")]
struct PyAgentIdentity {
    inner: RustIdentity,
}

#[pymethods]
impl PyAgentIdentity {
    /// Derive a deterministic identity from (name, project, seed?).
    ///
    /// Same inputs always produce the same Ed25519 keypair.
    #[new]
    #[pyo3(signature = (name, project, seed=None))]
    fn new(name: &str, project: &str, seed: Option<&[u8]>) -> PyResult<Self> {
        let inner = RustIdentity::derive(name, project, seed)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Reconstruct an identity from raw 32-byte secret key bytes.
    #[staticmethod]
    #[pyo3(signature = (name, project, secret_bytes))]
    fn from_secret_bytes(name: &str, project: &str, secret_bytes: &[u8]) -> PyResult<Self> {
        let inner = RustIdentity::from_secret_bytes(name, project, secret_bytes)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The agent's name.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    /// The agent's project.
    #[getter]
    fn project(&self) -> &str {
        &self.inner.project
    }

    /// 32-byte Ed25519 public key as `bytes`.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        Ok(PyBytes::new_bound(py, &self.inner.public_key()).into())
    }

    /// Hex-encoded public key.
    #[getter]
    fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    /// 32-byte Ed25519 secret key as `bytes`.  Treat as sensitive.
    #[getter]
    fn secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        Ok(PyBytes::new_bound(py, &self.inner.secret_bytes()).into())
    }

    /// Human-readable fingerprint: `ag:sha256:<16-hex-chars>`.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// Sign an arbitrary message.  Returns 64-byte Ed25519 signature.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<PyObject> {
        let sig = self.inner.sign(message);
        Ok(PyBytes::new_bound(py, &sig.to_bytes()).into())
    }

    /// Mint a compact binary token (~173 bytes).
    ///
    /// Parameters
    /// ----------
    /// scopes : list[str]
    ///     Permission scopes (e.g. ``["read:arxiv", "write:notes"]``).
    /// ttl_seconds : int, default 900
    ///     Token lifetime in seconds (1–86 400).
    /// max_calls : int, default 0
    ///     Per-token call quota.  0 = unlimited.
    #[pyo3(signature = (scopes=vec![], ttl_seconds=900, max_calls=0))]
    fn mint_token<'py>(
        &self,
        py: Python<'py>,
        scopes: Vec<String>,
        ttl_seconds: u64,
        max_calls: u32,
    ) -> PyResult<PyObject> {
        let token = RustTokenBuilder::new(&self.inner)
            .scopes(scopes)
            .ttl_seconds(ttl_seconds)
            .max_calls(max_calls)
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &token).into())
    }

    fn __repr__(&self) -> String {
        format!(
            "AgentIdentity(name={:?}, project={:?}, fingerprint={:?})",
            self.inner.name,
            self.inner.project,
            self.inner.fingerprint()
        )
    }
}

/// Verify a token and return its claims as a dict.
///
/// Parameters
/// ----------
/// token : bytes
///     Raw binary token (as returned by ``AgentIdentity.mint_token``).
/// expected_pubkey : bytes | None
///     If provided (32 bytes), the token's issuer must match.
///
/// Returns
/// -------
/// dict
///     Decoded claims with keys: ``name``, ``project``, ``scopes``,
///     ``issued_at``, ``expires_at``, ``max_calls``, ``token_id``,
///     ``issuer``, ``fingerprint``.
///
/// Raises
/// ------
/// RuntimeError
///     If the token is malformed, expired, or the signature is invalid.
#[pyfunction]
#[pyo3(signature = (token, expected_pubkey=None))]
fn verify_token<'py>(
    py: Python<'py>,
    token: &[u8],
    expected_pubkey: Option<&[u8]>,
) -> PyResult<PyObject> {
    let pk: Option<&[u8; 32]> = match expected_pubkey {
        Some(b) => {
            if b.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "expected_pubkey must be 32 bytes, got {}",
                    b.len()
                )));
            }
            Some(b.try_into().unwrap())
        }
        None => None,
    };

    let claims: RustClaims =
        rust_verify(token, pk).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let dict = PyDict::new_bound(py);
    dict.set_item("name", &claims.name)?;
    dict.set_item("project", &claims.project)?;
    dict.set_item("scopes", &claims.scopes)?;
    dict.set_item("issued_at", claims.issued_at)?;
    dict.set_item("expires_at", claims.expires_at)?;
    dict.set_item("max_calls", claims.max_calls)?;
    dict.set_item("token_id", claims.token_id)?;
    dict.set_item("issuer", PyBytes::new_bound(py, &claims.issuer))?;
    dict.set_item("fingerprint", claims.fingerprint())?;
    Ok(dict.into())
}

/// Check whether `granted` scope covers `requested` scope using wildcard rules.
///
/// Examples
/// --------
/// >>> scope_matches("read:*", "read:arxiv")
/// True
/// >>> scope_matches("read:arxiv", "write:arxiv")
/// False
#[pyfunction]
fn scope_matches(granted: &str, requested: &str) -> bool {
    agentid_core::scopes::Scope::matches(granted, requested)
}

/// The native extension module.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAgentIdentity>()?;
    m.add_function(wrap_pyfunction!(verify_token, m)?)?;
    m.add_function(wrap_pyfunction!(scope_matches, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
