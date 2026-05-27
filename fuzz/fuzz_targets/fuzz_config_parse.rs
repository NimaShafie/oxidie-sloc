// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
//
// Fuzz target: exercises TOML config deserialization.
// Run with: cargo fuzz run fuzz_config_parse

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Must not panic for any valid UTF-8 input.
    let _: Result<sloc_config::AppConfig, _> = toml::from_str(s);
});
