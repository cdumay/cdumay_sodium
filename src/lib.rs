//! [![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](./LICENSE)
//! [![cdumay_sodium on crates.io](https://img.shields.io/crates/v/cdumay_sodium)](https://crates.io/crates/cdumay_sodium)
//! [![cdumay_sodium on docs.rs](https://docs.rs/cdumay_sodium/badge.svg)](https://docs.rs/cdumay_sodium)
//! [![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/cdumay/cdumay_sodium)
//!
//! This crate provides functions and errors related to [libsodium](https://doc.libsodium.org/) sealed-box and secret-box usages.
//!
extern crate libsodium_sys as sodium;
mod errors;

pub use errors::*;

pub mod secretbox;

pub mod sealedbox;

/// Converts a vector of bytes (`Vec<u8>`) into a UTF-8 string.
///
/// This function attempts to convert the provided byte vector into a `String` using
/// UTF-8 encoding. If the conversion fails (i.e., the data is not valid UTF-8),
/// an error is returned with additional context information.
///
/// # Arguments
///
/// * `data` - The byte vector to convert.
/// * `context` - A `BTreeMap` containing additional context information for error reporting.
///
/// # Returns
///
/// Returns `Ok(String)` containing the decoded string if the data is valid UTF-8,
/// or an error of type [`cdumay_core::Error`] if the conversion fails.
///
/// # Errors
///
/// Returns an error if the input data is not valid UTF-8. The error includes a message
/// and the provided context for easier debugging.
/// 
fn vec_to_string(data: Vec<u8>, context: std::collections::BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<String> {
    String::from_utf8(data).map_err(|err| InvalidContent::new().with_message(err.to_string()).with_details(context.clone()).into())
}
