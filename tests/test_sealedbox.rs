#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    // Recipient's key pair: secret key, public key (correct order for libsodium)
    const PRIV_KEY_B64: &str = "Y+rH6koXiQbMri56PrACMmTWTQ8vjlOgJr/3+IUF1KU=";
    const PUB_KEY_B64: &str = "odxkRevQOBS/wvrZr9nr6uAsP2is2+frM/6mhCNqsz4=";
    const INPUT: &str = r#"{"hello": "world"}"#;

    #[test]
    fn test_cryptobox() {
        let context = BTreeMap::new();
        // Encrypt with recipient's public key
        let result = cdumay_sodium::sealedbox::crypt(INPUT, PUB_KEY_B64, context.clone());
        assert!(result.is_ok());

        // Decrypt with recipient's private key and public key
        let result = cdumay_sodium::sealedbox::decrypt(result.unwrap().as_str(), PRIV_KEY_B64, PUB_KEY_B64, context);
        assert!(result.is_ok());
        assert_eq!(INPUT, result.unwrap());
    }

    #[test]
    fn test_cryptobox_invalid_input() {
        let context = BTreeMap::new();
        let result = cdumay_sodium::sealedbox::decrypt("", PRIV_KEY_B64, PUB_KEY_B64, context.clone());
        assert!(result.is_ok());
        assert_eq!(String::new(), result.unwrap());
    }

    #[test]
    fn test_cryptobox_invalid_data() {
        let context = BTreeMap::new();
        let result = cdumay_sodium::sealedbox::decrypt(
            "ENbelIbhaDvOO51I3aZCyriFaiqcLEqg10h+gdL4KnuBNkH2CDbH4cCXa76JZhweGjmxpXccyDFcbpdEVEmSTogJ",
            PRIV_KEY_B64,
            PUB_KEY_B64,
            context.clone(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_decrypt_ciphertext_too_short() {
        let context = BTreeMap::new();
        use cdumay_base64::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use cdumay_base64::base64::Engine;
        // Less than SEALBYTES (48) bytes when decoded - e.g. 4 bytes base64
        let short_b64 = BASE64_STANDARD.encode([0u8; 4]);
        let result = cdumay_sodium::sealedbox::decrypt(&short_b64, PRIV_KEY_B64, PUB_KEY_B64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_crypt_invalid_public_key() {
        let context = BTreeMap::new();
        let result = cdumay_sodium::sealedbox::crypt(INPUT, "not-valid-base64!!!", context);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_crypt_public_key_wrong_length() {
        let context = BTreeMap::new();
        use cdumay_base64::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use cdumay_base64::base64::Engine;
        let wrong_len_key_b64 = BASE64_STANDARD.encode([0u8; 16]);
        let result = cdumay_sodium::sealedbox::crypt(INPUT, &wrong_len_key_b64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_decrypt_invalid_base64_data() {
        let context = BTreeMap::new();
        let result = cdumay_sodium::sealedbox::decrypt("not-valid-base64!!!", PRIV_KEY_B64, PUB_KEY_B64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_decrypt_invalid_base64_private_key() {
        let context = BTreeMap::new();
        let ciphertext = cdumay_sodium::sealedbox::crypt(INPUT, PUB_KEY_B64, context.clone()).unwrap();
        let result = cdumay_sodium::sealedbox::decrypt(&ciphertext, "not-valid-base64!!!", PUB_KEY_B64, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealedbox_decrypt_invalid_base64_public_key() {
        let context = BTreeMap::new();
        let ciphertext = cdumay_sodium::sealedbox::crypt(INPUT, PUB_KEY_B64, context.clone()).unwrap();
        let result = cdumay_sodium::sealedbox::decrypt(&ciphertext, PRIV_KEY_B64, "not-valid-base64!!!", context);
        assert!(result.is_err());
    }
}
