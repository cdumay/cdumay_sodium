# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2]

### Fixed

- **sealedbox::decrypt**: Corrected key order passed to libsodium `crypto_box_seal_open`. The C API expects `(pk, sk)` (public key, then secret key). The implementation was passing `(private_key, public_key)`; it now correctly passes `(public_key, private_key)`.
- **sealedbox::crypt**: Parameter was misnamed `private_key_b64` while the function expects the recipient's **public** key. Renamed to `public_key_b64` (API change; callers must pass the public key). Documentation and examples updated accordingly.

### Added

- **sealedbox::crypt**: Validation of decoded public key length (must be `crypto_box_PUBLICKEYBYTES`) before calling the C API. Returns a structured error instead of relying on libsodium behavior.
- **sealedbox::decrypt**: Validation that decoded ciphertext length is at least `crypto_box_SEALBYTES` before allocation and C call. Returns a clear error for too-short input instead of panicking or undefined behavior.
- Additional tests for secretbox: empty data, invalid key length, wrong key, invalid UTF-8 decryption, invalid base64 (data, key, nonce), crypt with invalid key.
- Additional tests for sealedbox: ciphertext too short, invalid base64 (data, private key, public key), public key wrong length. Doctests updated to use correct keys and round-trip example for decrypt.

### Changed

- **Dependencies**: Use base64 via the re-export from `cdumay_base64` instead of a direct `base64` dependency. Requires `cdumay_base64` ≥ 0.1.2 (which re-exports `base64`).
- **secretbox**: `into_secretbox_key` and `into_secretbox_nonce` now check length before converting to boxed slice, avoiding unnecessary allocation on error and simplifying the success path.
- **secretbox::crypt** and **sealedbox::crypt**: Removed redundant `.trim()` on base64-encoded output (standard base64 does not produce leading/trailing whitespace).
- **Performance**: Reduced unnecessary `context.clone()` in error/success paths where context is consumed (e.g. `vec_to_string`, sealedbox decrypt/crypt branches).

### Documentation

- **README**: Expanded with features, installation, usage examples for Secret Box and Sealed Box, error handling overview, and API summary.

---

For older versions, see the [git history](https://github.com/cdumay/cdumay_sodium/commits/main).
