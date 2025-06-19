use cdumay_core::define_errors;
use cdumay_error::{InvalidConfiguration, ValidationError};

define_errors! {
    InvalidBoxKeyLength = InvalidConfiguration,
    InvalidBoxNonceLength = InvalidConfiguration,
    FailedToOpenBox = ValidationError
}
