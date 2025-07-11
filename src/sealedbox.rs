//! Sealed boxes are designed to anonymously send messages to a recipient given their public key.
//!
//! Only the recipient can decrypt these messages using their private key. While the recipient can verify the integrity of the message, they cannot verify the identity of the sender.
//!
//! A message is encrypted using an ephemeral key pair, with the secret key being erased right after the encryption process.
//!
//! Without knowing the secret key used for a given message, the sender cannot decrypt the message later. Furthermore, without additional data, a message cannot be correlated with the identity of its sender.
use crate::{FailedToOpenSealedBox, vec_to_string};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use cdumay_core::ErrorConverter;
use std::collections::BTreeMap;

/// Decrypts data encrypted with a sealed box using libsodium.
///
/// This function attempts to decrypt the given base64-encoded data using the provided
/// base64-encoded private and public keys. The decryption is performed using the
/// `crypto_box_seal_open` function from libsodium. If decryption is successful, the
/// resulting plaintext is returned as a UTF-8 string. If any step fails (base64 decoding,
/// decryption, or UTF-8 conversion), an error with context is returned.
///
/// # Arguments
///
/// * `data` - The base64-encoded sealed box ciphertext to decrypt.
/// * `private_key_b64` - The base64-encoded private key.
/// * `public_key_b64` - The base64-encoded public key.
/// * `context` - A `BTreeMap` containing additional context information for error reporting.
///
/// # Returns
///
/// Returns `Ok(String)` containing the decrypted plaintext if successful, or an error
/// of type [`cdumay_core::Error`] if any step fails.
///
/// # Errors
///
/// Returns an error if:
/// - The input data or keys cannot be base64-decoded.
/// - The sealed box cannot be opened (decryption fails).
/// - The decrypted data is not valid UTF-8.
///
/// # Safety
///
/// This function calls `sodium::sodium_init()` and uses unsafe code to interact with
/// the libsodium C API. The caller must ensure that the provided keys and data are valid
/// and that libsodium is properly initialized.
///
/// # Example
///
/// ```
/// use std::collections::BTreeMap;
/// use serde_value::Value;
/// use cdumay_sodium::sealedbox::decrypt;
///
/// let data = "xSZKxMXGUVW1ONlS+R7lF/ZhjttkQzsbVei8gfif2S7ntsi+g6waekphBq/1lZ67eDOw8/3lwm6c8AbvvIcOHAD3";
/// let private_key = "odxkRevQOBS/wvrZr9nr6uAsP2is2+frM/6mhCNqsz4=";
/// let public_key = "Y+rH6koXiQbMri56PrACMmTWTQ8vjlOgJr/3+IUF1KU=";
/// let context = BTreeMap::<String, Value>::new();
/// let plaintext = decrypt(data, private_key, public_key, context).unwrap();
/// println!("Decrypted: {}", plaintext);
/// ```
pub fn decrypt(
    data: &str,
    private_key_b64: &str,
    public_key_b64: &str,
    context: BTreeMap<String, serde_value::Value>,
) -> cdumay_core::Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }
    let data_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(data), context.clone())?;
    let priv_key_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(private_key_b64), context.clone())?;
    let pub_key_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(public_key_b64), context.clone())?;

    unsafe {
        sodium::sodium_init();
        let mut decrypted = vec![0u8; data_decoded.len() - sodium::crypto_box_SEALBYTES as usize];
        let ret = sodium::crypto_box_seal_open(
            decrypted.as_mut_ptr(),
            data_decoded.as_ptr(),
            data_decoded.len() as u64,
            priv_key_decoded.as_ptr(),
            pub_key_decoded.as_ptr(),
        );
        match ret != 0 {
            true => Err(FailedToOpenSealedBox::new()
                .with_message("Decryption failed".to_string())
                .with_details(context.clone())
                .into()),
            false => vec_to_string(decrypted, context.clone()),
        }
    }
}

/// Encrypts data using a sealed box with libsodium.
///
/// This function encrypts the given plaintext data using the sealed box construction
/// (`crypto_box_seal`) from libsodium. The data is encrypted with the provided
/// base64-encoded public key, and the resulting ciphertext is returned as a base64-encoded string.
/// If any step fails (base64 decoding, encryption), an error with context is returned.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt as a UTF-8 string.
/// * `private_key_b64` - The base64-encoded public key to use for encryption.
/// * `context` - A `BTreeMap` containing additional context information for error reporting.
///
/// # Returns
///
/// Returns `Ok(String)` containing the base64-encoded sealed box ciphertext if successful,
/// or an error of type [`cdumay_core::Error`] if any step fails.
///
/// # Errors
///
/// Returns an error if:
/// - The provided public key cannot be base64-decoded.
/// - The encryption operation fails.
///
/// # Safety
///
/// This function calls `sodium::sodium_init()` and uses unsafe code to interact with
/// the libsodium C API. The caller must ensure that the provided key is valid and that
/// libsodium is properly initialized.
///
/// # Example
///
/// ```
/// use std::collections::BTreeMap;
/// use serde_value::Value;
/// use cdumay_sodium::sealedbox::crypt;
///
/// let data = "my secret message";
/// let private_key = "odxkRevQOBS/wvrZr9nr6uAsP2is2+frM/6mhCNqsz4=";
/// let context = BTreeMap::<String, Value>::new();
/// let ciphertext = crypt(data, private_key, context).unwrap();
/// println!("Encrypted (base64): {}", ciphertext);
/// ```

pub fn crypt(data: &str, private_key_b64: &str, context: BTreeMap<String, serde_value::Value>) -> cdumay_core::Result<String> {
    let priv_key_decoded = cdumay_base64::convert_decode_result!(BASE64_STANDARD.decode(private_key_b64), context.clone())?;

    unsafe {
        sodium::sodium_init();
        let mut ciphertext = vec![0u8; data.as_bytes().len() + sodium::crypto_box_SEALBYTES as usize];
        let ret = sodium::crypto_box_seal(ciphertext.as_mut_ptr(), data.as_ptr(), data.len() as u64, priv_key_decoded.as_ptr());
        match ret != 0 {
            true => Err(FailedToOpenSealedBox::new()
                .with_message("Encryption failed".to_string())
                .with_details(context.clone())
                .into()),
            false => Ok(BASE64_STANDARD.encode(ciphertext).trim().to_string()),
        }
    }
}
