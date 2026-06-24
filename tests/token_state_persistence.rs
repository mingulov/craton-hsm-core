// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end tests for token initialization-state persistence (Gap 1).
//!
//! Verifies that an initialized token — SO PIN, User PIN, label, and the
//! `initialized` / `user_pin_initialized` flags — survives a process restart,
//! simulated here by dropping a `Token` and constructing a fresh one from the
//! same on-disk `storage_path`.

use craton_hsm::config::HsmConfig;
use craton_hsm::pkcs11_abi::constants::{CKU_SO, CKU_USER};
use craton_hsm::token::token::Token;

/// Build a config rooted at a unique temp directory so concurrent test runs
/// do not collide on the shared storage path.
fn config_in_tempdir(tag: &str) -> (HsmConfig, std::path::PathBuf) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "craton-tokenstate-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).expect("create tempdir");

    let mut config = HsmConfig::default();
    config.token.storage_path = dir.clone();
    // Token-state persistence is gated on `persist_objects` (the full-
    // persistence opt-in), so enable it for these tests.
    config.token.persist_objects = true;
    // Pin a trivially-low PBKDF2 work factor explicitly so these tests are
    // instant in ANY build mode. The default would be 600,000 under
    // `cargo test --release` (only 1 under debug), which would make every
    // init/login/set_pin/unwrap in these tests do a real 600k-iteration KDF.
    config.security.pbkdf2_iterations = 1;
    (config, dir)
}

fn padded_label(s: &[u8]) -> [u8; 32] {
    let mut l = [b' '; 32];
    let n = s.len().min(32);
    l[..n].copy_from_slice(&s[..n]);
    l
}

#[test]
fn initialized_token_survives_restart() {
    let (config, dir) = config_in_tempdir("restart");
    let so_pin = b"SoPin123";
    let user_pin = b"UserPin1";
    let label = padded_label(b"PersistentToken");

    // --- First "boot": initialize the token and set the user PIN. ---
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        assert!(!token.is_initialized(), "fresh token must be uninitialized");

        token.init_token(so_pin, &label).expect("init_token");
        // init_pin requires an SO login.
        token.login(CKU_SO, so_pin).expect("SO login");
        token.init_pin(user_pin).expect("init_pin");
        token.logout().expect("logout");

        assert!(token.is_initialized());
        assert!(token.is_user_pin_initialized());
    }

    // --- Second "boot": a brand-new Token from the same storage path. ---
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);

        assert!(
            token.is_initialized(),
            "token must still be initialized after restart"
        );
        assert!(
            token.is_user_pin_initialized(),
            "user PIN must still be initialized after restart"
        );
        assert_eq!(*token.label.read(), label, "label must survive restart");

        // The restored PIN hashes must verify the original PINs.
        token
            .login(CKU_USER, user_pin)
            .expect("user login must succeed after restart");
        token.logout().expect("logout");

        token
            .login(CKU_SO, so_pin)
            .expect("SO login must succeed after restart");

        // A wrong PIN must still be rejected.
        let token2 = Token::new_with_config_for_slot(Some(&config), 0);
        assert!(
            token2.login(CKU_USER, b"WrongPin9").is_err(),
            "wrong PIN must be rejected after restart"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uninitialized_token_has_no_state_file() {
    let (config, dir) = config_in_tempdir("uninit");
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        assert!(!token.is_initialized());
    }
    // No init happened, so no token_state file should have been written.
    assert!(
        !dir.join("token_state_0.json").exists(),
        "no state file should exist for an untouched token"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reinit_rotates_state_and_invalidates_old_user_pin() {
    let (config, dir) = config_in_tempdir("reinit");
    let so_pin = b"SoPinAaa1";
    let user_pin_a = b"UserPinA1";

    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        token
            .init_token(so_pin, &padded_label(b"First"))
            .expect("init A");
        token.login(CKU_SO, so_pin).expect("SO login A");
        token.init_pin(user_pin_a).expect("init_pin A");
        token.logout().expect("logout A");
    }

    // Re-initialize: C_InitToken on an initialized token requires the SO PIN
    // to MATCH the existing one (it resets user state, it does not change the
    // SO PIN). The user PIN must be wiped as a result.
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        token
            .init_token(so_pin, &padded_label(b"Second"))
            .expect("re-init");
    }

    // After restart, the user PIN is gone but the SO PIN still works.
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        assert!(token.is_initialized());
        assert!(
            !token.is_user_pin_initialized(),
            "user PIN must be cleared by re-init"
        );
        assert_eq!(
            *token.label.read(),
            padded_label(b"Second"),
            "re-init label must survive restart"
        );
        // The old user PIN must no longer be usable.
        assert!(
            token.login(CKU_USER, user_pin_a).is_err(),
            "old user PIN must be rejected after re-init"
        );
        token
            .login(CKU_SO, so_pin)
            .expect("SO PIN must still work after re-init + restart");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn object_master_key_is_stable_across_pin_change_and_restart() {
    // The object master key (OMK) must be reproducible from the user PIN, must
    // survive a PIN change (only its wrapping changes), and must survive a
    // restart — otherwise persisted objects would become undecryptable.
    let (config, dir) = config_in_tempdir("omk");
    let so_pin = b"SoPin123";
    let user_pin = b"UserPin1";
    let new_pin = b"NewUserP2";

    let omk_initial;
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        token
            .init_token(so_pin, &padded_label(b"OMK"))
            .expect("init");
        token.login(CKU_SO, so_pin).expect("SO login");
        token.init_pin(user_pin).expect("init_pin");

        // OMK must be unwrappable with the user PIN, and a wrong PIN must fail.
        omk_initial = token
            .unwrap_object_key(user_pin)
            .expect("OMK must unwrap with correct PIN");
        assert!(
            token.unwrap_object_key(b"WrongPin9").is_none(),
            "OMK must not unwrap with a wrong PIN"
        );

        // Change the user PIN (requires a user login).
        token.logout().expect("logout SO");
        token.login(CKU_USER, user_pin).expect("user login");
        token.set_pin(user_pin, new_pin).expect("set_pin");

        // Same OMK, now unwrappable with the new PIN; the old PIN no longer works.
        let omk_after_change = token
            .unwrap_object_key(new_pin)
            .expect("OMK must unwrap with new PIN");
        assert_eq!(
            *omk_initial, *omk_after_change,
            "object master key must be unchanged by a PIN change"
        );
        assert!(
            token.unwrap_object_key(user_pin).is_none(),
            "old PIN must no longer unwrap the OMK after a PIN change"
        );
    }

    // After a restart, the OMK is still recoverable with the new PIN and equal
    // to the original — so any objects encrypted under it remain decryptable.
    {
        let token = Token::new_with_config_for_slot(Some(&config), 0);
        let omk_after_restart = token
            .unwrap_object_key(new_pin)
            .expect("OMK must unwrap after restart");
        assert_eq!(
            *omk_initial, *omk_after_restart,
            "object master key must survive a restart unchanged"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn separate_slots_have_independent_state() {
    let (config, dir) = config_in_tempdir("multislot");

    {
        let t0 = Token::new_with_config_for_slot(Some(&config), 0);
        let t1 = Token::new_with_config_for_slot(Some(&config), 1);
        t0.init_token(b"Slot0Pin1", &padded_label(b"Slot0"))
            .expect("init slot0");
        // Slot 1 is left uninitialized.
        let _ = t1;
    }

    {
        let t0 = Token::new_with_config_for_slot(Some(&config), 0);
        let t1 = Token::new_with_config_for_slot(Some(&config), 1);
        assert!(t0.is_initialized(), "slot 0 must persist as initialized");
        assert!(
            !t1.is_initialized(),
            "slot 1 must remain independent / uninitialized"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
