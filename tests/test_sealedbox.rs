#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    const PRIV_KEY_B64: &str = "odxkRevQOBS/wvrZr9nr6uAsP2is2+frM/6mhCNqsz4=";
    const PUB_KEY_B64: &str = "Y+rH6koXiQbMri56PrACMmTWTQ8vjlOgJr/3+IUF1KU=";
    const INPUT: &str = r#"{"hello": "world"}"#;

    #[test]
    fn test_cryptobox() {
        let context = BTreeMap::new();
        let result = cdumay_sodium::sealedbox::crypt(INPUT, PRIV_KEY_B64, context.clone());
        assert!(result.is_ok());

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
}
