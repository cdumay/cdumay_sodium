//! In Libsodium, secretbox is a high-level authenticated symmetric encryption API. It allows you to encrypt and authenticate messages 
//! using a shared secret key.
//! 
//! secretbox provides: 
//! 
//! * Confidentiality (the message is encrypted)
//! * Integrity (any modification of the ciphertext can be detected)
//! * Authenticity (you know the message came from someone who knows the shared key)
//! 
//! It uses the following construction under the hood:
//! * XSalsa20: a fast stream cipher for encryption.
//! * Poly1305: a cryptographic MAC (message authentication code) for authentication.
//! 
//! The result is an AEAD scheme (Authenticated Encryption with Associated Data), although secretbox itself doesn’t support additional associated 
//! data — everything is encrypted and authenticated together.
//! 
//! This module provides basic secretbox manipulations.

use crate::{InvalidBoxKeyLength, InvalidBoxNonceLength};
use sodiumoxide::crypto::secretbox;
use std::collections::BTreeMap;

/// Converts a `Vec<u8>` into a `secretbox::Key` if it has the correct length.
///
/// This function takes ownership of a `Vec<u8>` and attempts to convert it into a
/// `Box<[u8; secretbox::KEYBYTES]>`. If the input vector does not have the correct
/// length (`secretbox::KEYBYTES`), an error is returned with a detailed context.
///
/// # Arguments
///
/// * `v` - A vector of bytes expected to be exactly `secretbox::KEYBYTES` in length.
/// * `context` - A map containing additional contextual information, useful for debugging
///   or logging purposes if the conversion fails.
///
/// # Returns
///
/// Returns `Ok(secretbox::Key)` if the conversion is successful. Otherwise, returns
/// an error of type `cdumay_core::Error` (usually wrapping `InvalidBoxKeyLength`).
///
/// # Errors
///
/// This function will return an error if `v.len() != secretbox::KEYBYTES`.
///
pub fn into_secretbox_key(v: Vec<u8>, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<secretbox::Key> {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; secretbox::KEYBYTES]> = boxed_slice.try_into().map_err(|_| {
        InvalidBoxKeyLength::new()
            .with_message(format!("Invalid box_key length required: {}", secretbox::KEYBYTES))
            .with_details(context)
    })?;
    Ok(secretbox::Key(*boxed_array))
}

/// Converts a `Vec<u8>` into a `secretbox::Nonce` if it has the correct length.
///
/// This function takes ownership of a `Vec<u8>` and attempts to convert it into a
/// `Box<[u8; secretbox::NONCEBYTES]>`. If the input vector does not have the correct
/// length (`secretbox::NONCEBYTES`), an error is returned with contextual details.
///
/// # Arguments
///
/// * `v` - A vector of bytes expected to be exactly `secretbox::NONCEBYTES` in length.
/// * `context` - A BTreeMap containing additional context that will be attached to the error
///   in case of failure. Useful for debugging or logging.
///
/// # Returns
///
/// Returns `Ok(secretbox::Nonce)` if the conversion is successful. Otherwise, returns
/// a `cdumay_core::Error` (typically wrapping an `InvalidBoxNonceLength`).
///
/// # Errors
///
/// This function returns an error if `v.len() != secretbox::NONCEBYTES`.
/// 
pub fn into_secretbox_nonce(v: Vec<u8>, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<secretbox::Nonce> {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; secretbox::NONCEBYTES]> = boxed_slice.try_into().map_err(|_| {
        InvalidBoxNonceLength::new()
            .with_message(format!("Invalid box_nonce length required: {}", secretbox::NONCEBYTES))
            .with_details(context)
    })?;
    Ok(secretbox::Nonce(*boxed_array))
}
