#[cfg(test)]
mod test {
    use cdumay_base64::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use cdumay_base64::base64::Engine;
    use cdumay_sodium::secretbox;
    use sodiumoxide::crypto::secretbox as sb;
    use std::collections::BTreeMap;

    const SB_KEY_B64: &str = "llQgXXVGlyQcwvkd78uwNoa2jzKzquFjRrHDwQ/eJSU=";
    const INPUT: &str = r#"{"hello": "world"}"#;

    #[test]
    fn test_secretbox() {
        let context = BTreeMap::new();

        // SecretBox seal
        let result = secretbox::crypt(INPUT, SB_KEY_B64, context.clone());
        assert!(result.is_ok());
        let (nonce_b64, data_64) = result.unwrap();

        // SecretBox unseal
        let result = secretbox::decrypt(&data_64, SB_KEY_B64, &nonce_b64, context.clone());
        assert!(result.is_ok());
        assert_eq!(INPUT, result.unwrap());
    }

    #[test]
    fn test_secretbox_decrypt_empty_data() {
        let context = BTreeMap::new();
        let result = secretbox::decrypt("", SB_KEY_B64, "HZGeSXQLJlFNpQgGyvYkXj+jAL9d/15J", context);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_secretbox_invalid_nonce() {
        let context = BTreeMap::new();
        let result = secretbox::decrypt(INPUT, SB_KEY_B64, "llQgXXVGlyQcwvkd", context.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_invalid_key_length() {
        let context = BTreeMap::new();
        // Key decoded to 16 bytes instead of KEYBYTES (32)
        let short_key_b64 = BASE64_STANDARD.encode([0u8; 16]);
        let (nonce_b64, ciphertext_b64) = secretbox::crypt(INPUT, SB_KEY_B64, context.clone()).unwrap();
        let result = secretbox::decrypt(&ciphertext_b64, &short_key_b64, &nonce_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_decrypt_wrong_key() {
        let context = BTreeMap::new();
        let (nonce_b64, ciphertext_b64) = secretbox::crypt(INPUT, SB_KEY_B64, context.clone()).unwrap();
        // Different valid key (32 bytes)
        let wrong_key_b64 = BASE64_STANDARD.encode([1u8; 32]);
        let result = secretbox::decrypt(&ciphertext_b64, &wrong_key_b64, &nonce_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_decrypt_invalid_utf8() {
        let context = BTreeMap::new();
        let key_decoded = BASE64_STANDARD.decode(SB_KEY_B64).unwrap();
        let key_arr: [u8; sb::KEYBYTES] = key_decoded.as_slice().try_into().unwrap();
        let key = sb::Key(key_arr);
        let nonce = sb::gen_nonce();
        let plaintext_invalid_utf8 = vec![0xFF, 0xFE];
        let ciphertext = sb::seal(&plaintext_invalid_utf8, &nonce, &key);
        let data_b64 = BASE64_STANDARD.encode(ciphertext);
        let nonce_b64 = BASE64_STANDARD.encode(nonce.as_ref());
        let result = secretbox::decrypt(&data_b64, SB_KEY_B64, &nonce_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_crypt_invalid_key_base64() {
        let context = BTreeMap::new();
        let result = secretbox::crypt(INPUT, "not-valid-base64!!!", context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_crypt_invalid_key_length() {
        let context = BTreeMap::new();
        let short_key_b64 = BASE64_STANDARD.encode([0u8; 16]);
        let result = secretbox::crypt(INPUT, &short_key_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_decrypt_invalid_base64_data() {
        let context = BTreeMap::new();
        let result = secretbox::decrypt("not-valid-base64!!!", SB_KEY_B64, "HZGeSXQLJlFNpQgGyvYkXj+jAL9d/15J", context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_decrypt_invalid_base64_key() {
        let context = BTreeMap::new();
        let (nonce_b64, ciphertext_b64) = secretbox::crypt(INPUT, SB_KEY_B64, context.clone()).unwrap();
        let result = secretbox::decrypt(&ciphertext_b64, "not-valid-base64!!!", &nonce_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_secretbox_decrypt_invalid_base64_nonce() {
        let context = BTreeMap::new();
        let (_, ciphertext_b64) = secretbox::crypt(INPUT, SB_KEY_B64, context.clone()).unwrap();
        let result = secretbox::decrypt(&ciphertext_b64, SB_KEY_B64, "!!!", context);
        assert!(result.is_err());
    }
}
