#[cfg(test)]
mod test {
    use cdumay_sodium::secretbox;
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
        dbg!(&nonce_b64);
        dbg!(&data_64);

        // SecretBox unseal
        let result = secretbox::decrypt(&data_64, SB_KEY_B64, &nonce_b64, context.clone());
        assert!(result.is_ok());
        assert_eq!(INPUT, result.unwrap());
    }

    #[test]
    fn test_secretbox_invalid_nonce() {
        let context = BTreeMap::new();
        let result = secretbox::decrypt(INPUT, SB_KEY_B64, "llQgXXVGlyQcwvkd", context.clone());
        assert!(result.is_err());
    }
}
