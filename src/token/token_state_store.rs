// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]

//! Persists token initialization state (SO/User PIN hashes, label, and the
//! `initialized` / `user_pin_initialized` flags) to disk so a token survives
//! a process restart.
//!
//! Without this, the token's auth state lives only in memory: after a restart
//! the token re-appears uninitialized, no PIN can be verified, and persisted
//! objects (see `EncryptedStore`) are unreachable. This store closes that gap.
//!
//! # What is stored
//!
//! * `label` — the 32-byte PKCS#11 token label.
//! * `so_pin_hash` / `user_pin_hash` — PBKDF2 `salt || derived_key` blobs
//!   (the *same* format the in-memory [`Token`](crate::token::token::Token)
//!   already uses). These are **not** plaintext secrets, but they are an
//!   offline brute-force target, so the file is locked down to owner-only the
//!   same way [`LockoutStore`](crate::store::lockout_store::LockoutStore) is.
//! * `object_key_salt` — a stable 32-byte salt used to derive the
//!   `EncryptedStore` object-encryption key from the user PIN at login time.
//!   It is distinct from the user-PIN auth salt so the on-disk auth verifier
//!   can never equal the object-encryption key.
//! * `initialized` / `user_pin_initialized` — the lifecycle flags.
//!
//! # Format
//!
//! Plain JSON, written atomically (temp file + rename) with owner-only
//! permissions, mirroring [`LockoutStore`](crate::store::lockout_store::LockoutStore).
//! Binary fields are hex-encoded so
//! the file is human-inspectable and round-trips losslessly.
//!
//! # Corruption handling
//!
//! A missing file means "fresh token" (returns `None`). A corrupt or
//! unreadable file is logged loudly and also treated as "fresh" (`None`) —
//! we cannot authenticate against garbage, so the only safe interpretation is
//! that no usable initialization state exists. This matches the existing
//! owner-only threat model: an attacker who can corrupt this file already has
//! write access to the storage directory and could equally delete it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::CK_SLOT_ID;
use crate::store::encrypted_store::set_restrictive_permissions;

/// Serializable on-disk representation of a token's initialization state.
///
/// All binary fields are hex-encoded strings. `None` for a PIN-hash field
/// means that PIN has not been set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenStateData {
    pub initialized: bool,
    pub user_pin_initialized: bool,
    /// 32-byte token label, hex-encoded.
    pub label_hex: String,
    /// PBKDF2 `salt || derived_key` for the SO PIN, hex-encoded.
    pub so_pin_hash_hex: Option<String>,
    /// PBKDF2 `salt || derived_key` for the User PIN, hex-encoded.
    pub user_pin_hash_hex: Option<String>,
    /// Stable 32-byte salt for deriving the object-store key-encryption key
    /// (KEK) from the user PIN, hex-encoded. Present only once a user PIN has
    /// been set on a persistence-enabled token.
    pub object_key_salt_hex: Option<String>,
    /// The object master key (OMK), wrapped with the PIN-derived KEK via
    /// AES-256-GCM (`nonce || ciphertext`), hex-encoded. The OMK — not the PIN
    /// — is the actual object-encryption key, so a PIN change only re-wraps
    /// this blob and never requires re-encrypting stored objects.
    pub object_master_key_wrapped_hex: Option<String>,
}

/// Decoded, in-memory form of [`TokenStateData`] handed back to `Token` on
/// load. PIN hashes are wrapped in `Zeroizing` so they are cleared on drop.
pub struct RestoredTokenState {
    pub initialized: bool,
    pub user_pin_initialized: bool,
    pub label: Option<[u8; 32]>,
    pub so_pin_hash: Option<Zeroizing<Vec<u8>>>,
    pub user_pin_hash: Option<Zeroizing<Vec<u8>>>,
    pub object_key_salt: Option<Vec<u8>>,
    pub object_master_key_wrapped: Option<Vec<u8>>,
}

/// File-backed persistence for a single token's initialization state.
///
/// One file per slot (`token_state_<slot>.json`) so multi-slot deployments do
/// not collide on a shared path.
pub struct TokenStateStore {
    path: PathBuf,
}

impl TokenStateStore {
    /// Create a store for `slot_id` rooted at `storage_dir`. The file is
    /// created on first [`save`](Self::save).
    pub fn new(storage_dir: &std::path::Path, slot_id: CK_SLOT_ID) -> Self {
        Self {
            path: storage_dir.join(format!("token_state_{}.json", slot_id)),
        }
    }

    /// Load and decode persisted token state.
    ///
    /// Returns `None` when the file is absent (fresh token) or cannot be
    /// parsed/read (corruption — logged, treated as fresh). A token is only
    /// reported as `initialized` when an SO PIN hash is actually present;
    /// an `initialized=true` record missing its SO hash is inconsistent and
    /// is downgraded to uninitialized.
    pub fn load(&self) -> Option<RestoredTokenState> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("no token state file found, starting fresh");
                return None;
            }
            Err(e) => {
                tracing::error!(
                    "cannot read token state file ({}) — treating token as uninitialized",
                    e
                );
                return None;
            }
        };

        let data: TokenStateData = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    "token state file is corrupted ({}) — treating token as uninitialized",
                    e
                );
                return None;
            }
        };

        let decode_hash = |field: Option<String>| -> Option<Zeroizing<Vec<u8>>> {
            field.and_then(|h| hex::decode(h).ok()).map(Zeroizing::new)
        };

        let so_pin_hash = decode_hash(data.so_pin_hash_hex);
        let user_pin_hash = decode_hash(data.user_pin_hash_hex);

        // Consistency guard: an "initialized" token must have an SO PIN hash.
        let initialized = data.initialized && so_pin_hash.is_some();
        if data.initialized && so_pin_hash.is_none() {
            tracing::error!(
                "token state claims initialized but has no SO PIN hash — \
                 treating as uninitialized"
            );
        }
        // A user PIN can only be considered initialized if its hash decoded.
        let user_pin_initialized = data.user_pin_initialized && user_pin_hash.is_some();

        let label = match hex::decode(&data.label_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut l = [0u8; 32];
                l.copy_from_slice(&bytes);
                Some(l)
            }
            _ => None,
        };

        let object_key_salt = data
            .object_key_salt_hex
            .and_then(|h| hex::decode(h).ok())
            .filter(|s| s.len() == 32);

        let object_master_key_wrapped = data
            .object_master_key_wrapped_hex
            .and_then(|h| hex::decode(h).ok());

        tracing::info!(
            "loaded token state: initialized={}, user_pin_initialized={}",
            initialized,
            user_pin_initialized,
        );

        Some(RestoredTokenState {
            initialized,
            user_pin_initialized,
            label,
            so_pin_hash,
            user_pin_hash,
            object_key_salt,
            object_master_key_wrapped,
        })
    }

    /// Persist token state atomically (write-to-temp + rename).
    ///
    /// The file is locked down to owner-only (Unix mode 0o600 / Windows
    /// owner-only DACL) on both the temp file and the final path, exactly as
    /// [`LockoutStore::save`](crate::store::lockout_store::LockoutStore::save)
    /// does. Permission-set failure is fatal: a token-state file that cannot
    /// be locked down would expose PIN-hash material to other local users.
    pub fn save(&self, data: &TokenStateData) -> HsmResult<()> {
        let json = serde_json::to_string_pretty(data).map_err(|e| {
            tracing::error!("failed to serialize token state: {}", e);
            HsmError::GeneralError
        })?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
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

            // Belt-and-suspenders: on Unix this is a no-op if mode(0o600)
            // already took effect; on Windows it is the only thing that sets
            // a restrictive DACL. Fatal on failure — we must not write
            // PIN-hash material to a world-readable file.
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

        // Re-apply restrictive permissions on the final path (Windows may
        // inherit parent DACLs through the rename). Fatal on failure.
        set_restrictive_permissions(&self.path)?;

        Ok(())
    }

    /// Remove the token state file (called during token re-initialization
    /// failures or test cleanup). A missing file is not an error.
    #[allow(dead_code)]
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

    fn tmpdir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "craton-tss-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).expect("create tempdir");
        dir
    }

    #[test]
    fn load_missing_file_returns_none() {
        let dir = tmpdir("missing");
        let store = TokenStateStore::new(&dir, 0);
        assert!(store.load().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tmpdir("roundtrip");
        let store = TokenStateStore::new(&dir, 0);

        let so_hash = vec![0xABu8; 64];
        let user_hash = vec![0xCDu8; 64];
        let salt = vec![0x11u8; 32];
        let wrapped = vec![0x22u8; 60];
        let mut label = [b' '; 32];
        label[..5].copy_from_slice(b"hello");

        store
            .save(&TokenStateData {
                initialized: true,
                user_pin_initialized: true,
                label_hex: hex::encode(label),
                so_pin_hash_hex: Some(hex::encode(&so_hash)),
                user_pin_hash_hex: Some(hex::encode(&user_hash)),
                object_key_salt_hex: Some(hex::encode(&salt)),
                object_master_key_wrapped_hex: Some(hex::encode(&wrapped)),
            })
            .expect("save must succeed");

        let restored = store.load().expect("must load");
        assert!(restored.initialized);
        assert!(restored.user_pin_initialized);
        assert_eq!(restored.label, Some(label));
        assert_eq!(restored.so_pin_hash.as_deref(), Some(&so_hash));
        assert_eq!(restored.user_pin_hash.as_deref(), Some(&user_hash));
        assert_eq!(restored.object_key_salt, Some(salt));
        assert_eq!(restored.object_master_key_wrapped, Some(wrapped));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initialized_without_so_hash_is_downgraded() {
        let dir = tmpdir("inconsistent");
        let store = TokenStateStore::new(&dir, 0);
        store
            .save(&TokenStateData {
                initialized: true,
                user_pin_initialized: false,
                label_hex: hex::encode([b' '; 32]),
                so_pin_hash_hex: None,
                user_pin_hash_hex: None,
                object_key_salt_hex: None,
                object_master_key_wrapped_hex: None,
            })
            .expect("save");
        let restored = store.load().expect("load");
        assert!(
            !restored.initialized,
            "initialized must be downgraded when SO hash is absent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_loads_as_none() {
        let dir = tmpdir("corrupt");
        let store = TokenStateStore::new(&dir, 0);
        std::fs::write(dir.join("token_state_0.json"), b"{not valid json").unwrap();
        assert!(store.load().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let store = TokenStateStore::new(&dir, 0);
        store
            .save(&TokenStateData::default())
            .expect("save must succeed");
        let meta = std::fs::metadata(dir.join("token_state_0.json")).expect("stat");
        assert_eq!(
            meta.permissions().mode() & 0o077,
            0,
            "token state file must be owner-only (0o600)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
