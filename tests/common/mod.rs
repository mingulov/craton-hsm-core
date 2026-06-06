// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Shared setup for PKCS#11 integration tests.
//!
//! Default `cargo test` builds embed the all-zero placeholder integrity public
//! key. The §9.4 software-integrity POST requires an explicit dev bypass for
//! those unsigned binaries. This module enables that bypass once per test
//! process before any `C_Initialize` call.

#![allow(unsafe_code)]

use std::sync::Once;

static BYPASS: Once = Once::new();

/// Enable the documented dev-only integrity bypass for unsigned debug builds.
pub fn enable_integrity_bypass() {
    BYPASS.call_once(|| unsafe {
        std::env::set_var("CRATON_HSM_INTEGRITY_BYPASS", "unsafe-dev-only");
    });
}

#[ctor::ctor]
fn auto_enable_integrity_bypass() {
    enable_integrity_bypass();
}
