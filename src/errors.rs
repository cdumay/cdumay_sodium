use cdumay_core::define_errors;
use cdumay_error::{InvalidConfiguration, ValidationError};

define_errors! {
    InvalidBoxKeyLength = InvalidConfiguration,
    InvalidBoxNonceLength = InvalidConfiguration,
    InvalidContent = ValidationError,
    FailedToOpenSecretBox = ValidationError,
    FailedToOpenSealedBox = ValidationError,
}
