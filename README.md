# cdumay_sodium

[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](./LICENSE)
[![cdumay_sodium on crates.io](https://img.shields.io/crates/v/cdumay_sodium)](https://crates.io/crates/cdumay_sodium)
[![cdumay_sodium on docs.rs](https://docs.rs/cdumay_sodium/badge.svg)](https://docs.rs/cdumay_sodium)
[![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/cdumay/cdumay_sodium)

This crate provides functions and errors related to [libsodium](https://doc.libsodium.org/) usage.

Example of secretbox Nonce manipulation:

```rust
use std::collections::BTreeMap;
use serde_value::Value;
use sodiumoxide::crypto::secretbox;
use cdumay_sodium::secretbox::into_secretbox_nonce;

let nonce_bytes = vec![0u8; secretbox::NONCEBYTES];
let context = BTreeMap::new();

let nonce_result = into_secretbox_nonce(nonce_bytes, context);
assert!(nonce_result.is_ok());
```
Example of secret box key manipulation:

```rust
use std::collections::BTreeMap;
use serde_value::Value;
use sodiumoxide::crypto::secretbox;
use cdumay_sodium::secretbox::into_secretbox_key;

let key_bytes = vec![0u8; secretbox::KEYBYTES];
let context = BTreeMap::new();

let key_result = into_secretbox_key(key_bytes, context);
assert!(key_result.is_ok());
```
