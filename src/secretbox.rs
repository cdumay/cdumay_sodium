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

use crate::{FailedToOpenSecretBox, InvalidBoxKeyLength, InvalidBoxNonceLength, vec_to_string};
use cdumay_base64::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cdumay_base64::base64::Engine;
use cdumay_core::ErrorConverter;
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
fn into_secretbox_key(v: Vec<u8>, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<secretbox::Key> {
    if v.len() != secretbox::KEYBYTES {
        return Err(InvalidBoxKeyLength::new()
            .with_message(format!("Invalid box_key length required: {}", secretbox::KEYBYTES))
            .with_details(context)
            .into());
    }
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; secretbox::KEYBYTES]> = boxed_slice.try_into().unwrap_or_else(|_| unreachable!());
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
fn into_secretbox_nonce(v: Vec<u8>, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<secretbox::Nonce> {
    if v.len() != secretbox::NONCEBYTES {
        return Err(InvalidBoxNonceLength::new()
            .with_message(format!("Invalid box_nonce length required: {}", secretbox::NONCEBYTES))
            .with_details(context)
            .into());
    }
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[u8; secretbox::NONCEBYTES]> = boxed_slice.try_into().unwrap_or_else(|_| unreachable!());
    Ok(secretbox::Nonce(*boxed_array))
}

/// Decrypts data encrypted with libsodium's SecretBox using a provided key and nonce.
///
/// This function takes base64-encoded ciphertext, key, and nonce, decodes them,
/// and attempts to decrypt the data using the SecretBox algorithm. If decryption is
/// successful, the plaintext is returned as a UTF-8 string. If any step fails
/// (base64 decoding, nonce/key conversion, decryption, or UTF-8 conversion), an error
/// with context is returned.
///
/// # Arguments
///
/// * `data_b64` - The base64-encoded ciphertext to decrypt.
/// * `sb_key_b64` - The base64-encoded secret key for SecretBox.
/// * `nonce_b64` - The base64-encoded nonce for SecretBox.
/// * `context` - A `BTreeMap` containing additional context information for error reporting.
///
/// # Returns
///
/// Returns `Ok(String)` containing the decrypted plaintext if successful,
/// or an error of type [`cdumay_core::Error`] if any step fails.
///
/// # Errors
///
/// Returns an error if:
/// - Any of the input strings cannot be base64-decoded.
/// - The key or nonce cannot be converted to the required format.
/// - The decryption fails (e.g., authentication error).
/// - The decrypted data is not valid UTF-8.
///
/// # Example
///
/// ```
/// use std::collections::BTreeMap;
/// use serde_value::Value;
/// use cdumay_sodium::secretbox::decrypt;
///
/// let data_b64 = "sUm+U20INMw6G4tfovoe4YSPYqzYdhfPhZ2v5U9Mu6tYIQ==";
/// let sb_key_b64 = "llQgXXVGlyQcwvkd78uwNoa2jzKzquFjRrHDwQ/eJSU=";
/// let nonce_b64 = "HZGeSXQLJlFNpQgGyvYkXj+jAL9d/15J";
/// let context = BTreeMap::<String, Value>::new();
/// let plaintext = decrypt(data_b64, sb_key_b64, nonce_b64, context).unwrap();
/// println!("Decrypted: {}", plaintext);
/// ```
pub fn decrypt(data_b64: &str, sb_key_b64: &str, nonce_b64: &str, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<String> {
    if data_b64.is_empty() {
        return Ok(String::new());
    }

    let data_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(data_b64), context.clone())?;
    let sb_key_b64_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(sb_key_b64), context.clone())?;
    let nonce_b64_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(nonce_b64), context.clone())?;

    match secretbox::open(
        data_decoded.as_slice(),
        &into_secretbox_nonce(nonce_b64_decoded, context.clone())?,
        &into_secretbox_key(sb_key_b64_decoded, context.clone())?,
    ) {
        Ok(decrypted) => vec_to_string(decrypted, context.clone()),
        Err(_) => Err(FailedToOpenSecretBox::new()
            .with_message("Decryption failed".to_string())
            .with_details(context)
            .into()),
    }
}

/// Encrypts data using libsodium's SecretBox and returns base64-encoded ciphertext and nonce.
///
/// This function encrypts the provided plaintext data using the SecretBox algorithm and a
/// base64-encoded secret key. It generates a random nonce for each encryption operation.
/// The function returns a tuple containing the base64-encoded nonce and the base64-encoded
/// ciphertext. If any step fails (base64 decoding, key conversion, encryption), an error
/// with context is returned.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt as a UTF-8 string.
/// * `sb_key_b64` - The base64-encoded secret key for SecretBox.
/// * `context` - A `BTreeMap` containing additional context information for error reporting.
///
/// # Returns
///
/// Returns `Ok((String, String))` containing the base64-encoded nonce and ciphertext if successful,
/// or an error of type [`cdumay_core::Error`] if any step fails.
///
/// # Errors
///
/// Returns an error if:
/// - The provided secret key cannot be base64-decoded.
/// - The key cannot be converted to the required format.
/// - The encryption operation fails (unexpected).
///
/// # Example
///
/// ```
/// use std::collections::BTreeMap;
/// use serde_value::Value;
/// use cdumay_sodium::secretbox::crypt;
///
/// let data = "my secret message";
/// let sb_key_b64 = "llQgXXVGlyQcwvkd78uwNoa2jzKzquFjRrHDwQ/eJSU=";
/// let context = BTreeMap::<String, Value>::new();
/// let (nonce_b64, ciphertext_b64) = crypt(data, sb_key_b64, context).unwrap();
/// println!("Nonce (base64): {}", nonce_b64);
/// println!("Ciphertext (base64): {}", ciphertext_b64);
/// ```
pub fn crypt(data: &str, sb_key_b64: &str, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<(String, String)> {
    let nonce = secretbox::gen_nonce();
    let sb_key_b64_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(sb_key_b64), context.clone())?;
    let ciphertext = secretbox::seal(data.as_bytes(), &nonce, &into_secretbox_key(sb_key_b64_decoded, context.clone())?);
    Ok((
        BASE64_STANDARD.encode(nonce.as_ref()),
        BASE64_STANDARD.encode(ciphertext),
    ))
}
