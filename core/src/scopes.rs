//! Scope parsing and matching.
//!
//! Scopes are colon-delimited strings like `read:arxiv` or `write:notes:draft`.
//! `*` matches a single segment; the bare `*` matches everything.
//!
//! ```text
//!   "read:arxiv"   matches "read:arxiv"
//!   "read:*"       matches "read:arxiv", "read:notes"
//!   "*"            matches "anything:goes:here"
//!   "*:papers"     matches "read:papers", "write:papers"
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum scope length, in bytes. Constrained by the 1-byte length prefix in
/// the wire format.
pub const MAX_SCOPE_LEN: usize = u8::MAX as usize;

#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("scope too long: max {max} bytes, got {got}", max = MAX_SCOPE_LEN)]
    TooLong { got: usize },
    #[error("scope contains a NUL byte")]
    ContainsNul,
    #[error("scope must not be empty")]
    Empty,
    #[error("scope segment must not be empty (consecutive ':')")]
    EmptySegment,
}

/// A validated scope string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(String);

impl Scope {
    pub fn parse(s: &str) -> Result<Self, ScopeError> {
        if s.is_empty() {
            return Err(ScopeError::Empty);
        }
        if s.len() > MAX_SCOPE_LEN {
            return Err(ScopeError::TooLong { got: s.len() });
        }
        if s.contains('\0') {
            return Err(ScopeError::ContainsNul);
        }
        if s.split(':').any(str::is_empty) {
            return Err(ScopeError::EmptySegment);
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if `granted` covers `requested` per the wildcard rules.
    pub fn matches(granted: &str, requested: &str) -> bool {
        if granted == "*" {
            return true;
        }
        let g_parts: Vec<&str> = granted.split(':').collect();
        let r_parts: Vec<&str> = requested.split(':').collect();
        if g_parts.len() != r_parts.len() {
            return false;
        }
        g_parts
            .iter()
            .zip(r_parts.iter())
            .all(|(g, r)| *g == "*" || *g == *r)
    }

    /// Returns `true` if any of `granted` covers `requested`.
    pub fn matches_any<'a, I>(granted: I, requested: &str) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        granted.into_iter().any(|g| Self::matches(g, requested))
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Scope {
    type Err = ScopeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact() {
        assert!(Scope::matches("read:arxiv", "read:arxiv"));
    }

    #[test]
    fn segment_wildcard() {
        assert!(Scope::matches("read:*", "read:arxiv"));
        assert!(Scope::matches("*:papers", "read:papers"));
    }

    #[test]
    fn full_wildcard() {
        assert!(Scope::matches("*", "anything:goes"));
        assert!(Scope::matches("*", "x"));
    }

    #[test]
    fn no_match() {
        assert!(!Scope::matches("read:arxiv", "write:arxiv"));
        assert!(!Scope::matches("read:arxiv", "read:arxiv:v2"));
    }

    #[test]
    fn matches_any_works() {
        let granted = ["read:*", "write:notes"];
        assert!(Scope::matches_any(granted.iter().copied(), "read:arxiv"));
        assert!(!Scope::matches_any(granted.iter().copied(), "delete:notes"));
    }

    #[test]
    fn rejects_invalid() {
        assert!(matches!(Scope::parse(""), Err(ScopeError::Empty)));
        assert!(matches!(Scope::parse("a::b"), Err(ScopeError::EmptySegment)));
        assert!(matches!(Scope::parse("a\0b"), Err(ScopeError::ContainsNul)));
    }
}
