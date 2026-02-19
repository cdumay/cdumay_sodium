# cdumay_sodium

[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](./LICENSE)
[![cdumay_sodium on crates.io](https://img.shields.io/crates/v/cdumay_sodium)](https://crates.io/crates/cdumay_sodium)
[![cdumay_sodium on docs.rs](https://docs.rs/cdumay_sodium/badge.svg)](https://docs.rs/cdumay_sodium)
[![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/cdumay/cdumay_sodium)

A Rust library providing high-level bindings for [libsodium](https://doc.libsodium.org/) **Secret Box** (authenticated symmetric encryption) and **Sealed Box** (anonymous public-key encryption). All inputs and outputs use base64-encoded strings and integrate with the [cdumay_core](https://crates.io/crates/cdumay_core) error framework.

## Features

- **Secret Box**: Symmetric authenticated encryption (XSalsa20-Poly1305) with a shared key and nonce. Confidentiality, integrity, and authenticity.
- **Sealed Box**: Anonymous encryption to a recipient’s public key; only the recipient can decrypt with their private key. No sender authentication.
- Base64 encoding/decoding for keys, nonces, and ciphertexts (via [cdumay_base64](https://crates.io/crates/cdumay_base64)).
- Structured errors with context ([cdumay_error](https://crates.io/crates/cdumay_error) / cdumay_core).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
cdumay_sodium = "0.2"
```

You need **libsodium** installed on your system (the [libsodium-sys](https://crates.io/crates/libsodium-sys) crate is used as backend).

## Usage

### Secret Box (symmetric encryption)

Encrypt and decrypt with a shared secret key (32 bytes, base64-encoded). A random nonce is generated for each encryption.

```rust
use std::collections::BTreeMap;
use serde_value::Value;
use cdumay_sodium::secretbox;

let key_b64 = "llQgXXVGlyQcwvkd78uwNoa2jzKzquFjRrHDwQ/eJSU=";
let context = BTreeMap::<String, Value>::new();

// Encrypt
let (nonce_b64, ciphertext_b64) = secretbox::crypt("my secret message", key_b64, context.clone()).unwrap();

// Decrypt
let plaintext = secretbox::decrypt(&ciphertext_b64, key_b64, &nonce_b64, context).unwrap();
assert_eq!(plaintext, "my secret message");
```

### Sealed Box (anonymous public-key encryption)

Encrypt with the recipient’s public key; decrypt with the recipient’s private and public key. The sender cannot be identified from the ciphertext alone.

```rust
use std::collections::BTreeMap;
use serde_value::Value;
use cdumay_sodium::sealedbox;

let public_key_b64 = "odxkRevQOBS/wvrZr9nr6uAsP2is2+frM/6mhCNqsz4=";
let private_key_b64 = "Y+rH6koXiQbMri56PrACMmTWTQ8vjlOgJr/3+IUF1KU=";
let context = BTreeMap::<String, Value>::new();

// Encrypt for the recipient (using their public key)
let ciphertext_b64 = sealedbox::crypt("secret message", public_key_b64, context.clone()).unwrap();

// Decrypt as the recipient (using their private + public key)
let plaintext = sealedbox::decrypt(&ciphertext_b64, private_key_b64, public_key_b64, context).unwrap();
assert_eq!(plaintext, "secret message");
```

### Error handling

All functions return `cdumay_core::Result<...>`. Errors carry a message and an optional context `BTreeMap` for debugging. Example error types:

- `InvalidBoxKeyLength` / `InvalidBoxNonceLength`: wrong key or nonce size (Secret Box).
- `FailedToOpenSecretBox`: decryption failed (e.g. wrong key, tampered data).
- `FailedToOpenSealedBox`: decryption failed or invalid sealed box / key length.
- `InvalidContent`: decrypted data is not valid UTF-8.

## API overview

| Module      | Functions | Description |
|------------|-----------|-------------|
| `secretbox` | `crypt`, `decrypt` | Symmetric authenticated encryption (key + nonce). |
| `sealedbox` | `crypt`, `decrypt` | Anonymous encryption to a public key. |

Keys, nonces, and ciphertexts are passed as base64-encoded strings; plaintexts are UTF-8 strings.

## Documentation

Full API docs: [docs.rs/cdumay_sodium](https://docs.rs/cdumay_sodium)

## License

BSD-3-Clause. See [LICENSE](./LICENSE).
