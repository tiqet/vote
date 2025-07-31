//! Error handling for the voting system

/// Result type alias for the voting system
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the voting system
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Cryptographic operation errors
    #[error("Cryptographic error: {message}")]
    Crypto { message: String },

    /// Voting-specific errors
    #[error("Voting error: {message}")]
    Voting { message: String },

    /// Validation errors
    #[error("Validation failed: {field}")]
    Validation { field: String },

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Generic internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl Error {
    /// Create a new crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a new voting error
    pub fn voting(message: impl Into<String>) -> Self {
        Self::Voting {
            message: message.into(),
        }
    }

    /// Create a new validation error
    pub fn validation(field: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
        }
    }

    /// Create a new internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

/// Convenience macros for creating specific error types
#[macro_export]
macro_rules! crypto_error {
    ($msg:expr) => {
        $crate::Error::crypto($msg)
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::crypto(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! voting_error {
    ($msg:expr) => {
        $crate::Error::voting($msg)
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::voting(format!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let crypto_err = Error::crypto("test crypto error");
        assert!(matches!(crypto_err, Error::Crypto { .. }));

        let voting_err = Error::voting("test voting error");
        assert!(matches!(voting_err, Error::Voting { .. }));

        let validation_err = Error::validation("test_field");
        assert!(matches!(validation_err, Error::Validation { .. }));
    }

    #[test]
    fn test_error_macros() {
        let crypto_err = crypto_error!("test error");
        assert!(matches!(crypto_err, Error::Crypto { .. }));

        let voting_err = voting_error!("test error");
        assert!(matches!(voting_err, Error::Voting { .. }));
    }
}
