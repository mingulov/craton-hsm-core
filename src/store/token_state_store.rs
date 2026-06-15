// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

//! Persists token initialization state (SO/user PIN hashes, `initialized` flags,
//! and label) to disk so a provisioned token survives process restarts.
//!
//! Without this, `Token` keeps its PIN hashes in memory only: a token initialized
//! in one process (e.g. via `C_InitToken`/`C_InitPIN`) is invisible to the next
//! process, so `C_Login` fails with `CKR_TOKEN_NOT_RECOGNIZED`. That breaks every
//! multi-process caller of the in-process module.
//!
//! The stored PIN hashes are salted PBKDF2-HMAC-SHA256 digests (see
//! `Token::hash_pin`) - non-reversible, like `/etc/shadow` - so they are stored
//! as JSON without additional encryption, but the file is locked down to
//! owner-only and written atomically (write-to-temp + fsync + rename), mirroring
//! `LockoutStore`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{HsmError, HsmResult};
use crate::store::encrypted_store::set_restrictive_permissions;

/// Persisted initialization state for a single token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenStateData {
    /// Salted PBKDF2 hash of the SO PIN, if the token has been initialized.
    pub so_pin_hash: Option<Vec<u8>>,
    /// Salted PBKDF2 hash of the user PIN, if the user PIN has been set.
    pub user_pin_hash: Option<Vec<u8>>,
    /// Whether `C_InitToken` has run (the token has an SO PIN).
    pub initialized: bool,
    /// Whether the user PIN has been set.
    pub user_pin_initialized: bool,
    /// The 32-byte, space-padded token label.
    pub label: Vec<u8>,
}

/// File-backed persistence for token initialization state.
pub struct TokenStateStore {
    path: PathBuf,
}

impl TokenStateStore {
    /// Create a new token-state store. The file is created on first `save()`.
    pub fn new(storage_dir: &std::path::Path) -> Self {
        Self {
            path: storage_dir.join("token_state.json"),
        }
    }

    /// Load persisted token state. Returns `None` if the file does not exist
    /// (fresh, unprovisioned token) or is corrupted/unreadable. Failing to a
    /// `None` (unprovisioned) state is the safe default: callers cannot log in
    /// to a token that reports no SO/user PIN, so no unauthorized access is
    /// possible - an operator must re-initialize.
    pub fn load(&self) -> Option<TokenStateData> {
        match std::fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<TokenStateData>(&content) {
                Ok(data) => {
                    tracing::info!(
                        "loaded token state: initialized={}, user_pin_initialized={}",
                        data.initialized,
                        data.user_pin_initialized,
                    );
                    Some(data)
                }
                Err(e) => {
                    tracing::error!(
                        "token state file is corrupted ({}); treating the token as \
                         unprovisioned (re-initialization required)",
                        e
                    );
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("no token state file found, starting unprovisioned");
                None
            }
            Err(e) => {
                tracing::error!(
                    "cannot read token state file ({}); treating the token as \
                     unprovisioned (re-initialization required)",
                    e
                );
                None
            }
        }
    }

    /// Persist token state atomically (write-to-temp + fsync + rename), locking
    /// the file down to owner-only. Permission-set failure is fatal: a token
    /// state file that cannot be locked down must not be written, since a later
    /// boot would read attacker-controlled PIN hashes.
    pub fn save(&self, data: &TokenStateData) -> HsmResult<()> {
        let json = serde_json::to_string_pretty(data).map_err(|e| {
            tracing::error!("failed to serialize token state: {}", e);
            HsmError::GeneralError
        })?;

        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    tracing::error!("failed to create token state directory: {}", e);
                    HsmError::GeneralError
                })?;
            }
        }

        let tmp_path = self.path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp_path).map_err(|e| {
                tracing::error!("failed to open token state temp file: {}", e);
                HsmError::GeneralError
            })?;

            if let Err(e) = set_restrictive_permissions(&tmp_path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }

            use std::io::Write;
            if let Err(e) = file.write_all(json.as_bytes()) {
                tracing::error!("failed to write token state temp file: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(HsmError::GeneralError);
            }
            if let Err(e) = file.sync_all() {
                tracing::error!("failed to fsync token state temp file: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(HsmError::GeneralError);
            }
        }

        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            tracing::error!("failed to rename token state file: {}", e);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(HsmError::GeneralError);
        }

        set_restrictive_permissions(&self.path)?;
        Ok(())
    }

    /// Remove the token state file (called during token re-initialization).
    pub fn clear(&self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("failed to remove token state file: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_state_store_roundtrip() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let store = TokenStateStore::new(dir.path());

        // 1. Loading from non-existent file returns None
        assert!(store.load().is_none());

        // 2. Save state
        let data = TokenStateData {
            so_pin_hash: Some(vec![1, 2, 3]),
            user_pin_hash: Some(vec![4, 5, 6]),
            initialized: true,
            user_pin_initialized: true,
            label: vec![7u8; 32],
        };
        store.save(&data).expect("save must succeed");

        // 3. Load state matches
        let loaded = store.load().expect("load must succeed");
        assert_eq!(loaded.so_pin_hash, data.so_pin_hash);
        assert_eq!(loaded.user_pin_hash, data.user_pin_hash);
        assert_eq!(loaded.initialized, data.initialized);
        assert_eq!(loaded.user_pin_initialized, data.user_pin_initialized);
        assert_eq!(loaded.label, data.label);

        // 4. Permissions (unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(dir.path().join("token_state.json")).expect("stat file");
            let mode = meta.permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "token state file mode {:o} grants group/world access - must be 0o600",
                mode & 0o777,
            );
        }

        // 5. Corrupted file returns None
        std::fs::write(dir.path().join("token_state.json"), b"corrupted data").unwrap();
        assert!(store.load().is_none());

        // 6. Clear removes file
        store.clear();
        assert!(store.load().is_none());
    }
}

