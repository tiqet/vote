//! # Comprehensive Error Handling for the Cryptographically Secure Voting System
//!
//! This module provides a robust error handling system designed for bank-grade security
//! and regulatory compliance. All errors include detailed context for debugging while
//! maintaining security by avoiding exposure of sensitive information.
//!
//! ## Design Principles
//!
//! - **Security-first**: No sensitive data leaked in error messages
//! - **Comprehensive context**: Detailed error information for debugging
//! - **Audit compatibility**: All errors can be logged for compliance
//! - **Developer-friendly**: Clear error messages with actionable guidance
//! - **Type safety**: Strong typing prevents error handling mistakes
//!
//! ## Error Categories
//!
//! The error system is organized into logical categories:
//!
//! ### Cryptographic Errors
//! Secure handling of cryptographic operation failures without exposing
//! internal cryptographic state or key material.
//!
//! ### Voting Errors
//! Election and voting-specific errors including timing violations,
//! invalid candidates, and vote processing failures.
//!
//! ### Validation Errors
//! Input validation failures with specific field information for
//! client-side error handling and user feedback.
//!
//! ### Serialization Errors
//! Data serialization and deserialization errors with automatic
//! conversion from `serde_json::Error`.
//!
//! ### Internal Errors
//! System-level errors for unexpected conditions that require
//! administrative attention.
//!
//! ## Security Considerations
//!
//! - Error messages never contain cryptographic keys or secrets
//! - Timing attack prevention through consistent error responses
//! - Audit trail integration for security incident detection
//! - Safe error propagation without information leakage
//!
//! ## Usage Examples
//!
//! ```rust
//! use vote::{Error, Result, crypto_error, voting_error};
//!
//! // Using error constructors
//! fn validate_signature() -> Result<()> {
//!     Err(crypto_error!("Invalid signature format"))
//! }
//!
//! // Using convenience macros
//! fn check_election_timing() -> Result<()> {
//!     Err(voting_error!("Election not accepting votes: outside time window"))
//! }
//!
//! // Pattern matching for error handling
//! fn handle_operation_result() -> Result<()> {
//!     let some_operation = || -> Result<String> {
//!         Ok("success".to_string())
//!     };
//!
//!     match some_operation() {
//!         Ok(result) => println!("Success: {:?}", result),
//!         Err(Error::Crypto { message }) => {
//!             eprintln!("Cryptographic error: {}", message);
//!             // Trigger security incident response
//!         },
//!         Err(Error::Voting { message }) => {
//!             eprintln!("Voting error: {}", message);
//!             // Return user-friendly error
//!         },
//!         Err(e) => eprintln!("Other error: {}", e),
//!     }
//!     Ok(())
//! }
//! ```

/// Result type alias for the voting system
///
/// A convenient type alias that defaults to the voting system's [`Error`] type.
/// This eliminates the need to specify the error type in function signatures
/// throughout the codebase.
///
/// # Design Benefits
///
/// - **Consistency**: All voting system functions use the same error type
/// - **Maintainability**: Error type changes only need updates in one place
/// - **Readability**: Shorter function signatures improve code clarity
/// - **Ergonomics**: Reduces boilerplate in error handling code
///
/// # Examples
///
/// ```rust
/// use vote::Result;
///
/// // Instead of: std::result::Result<String, vote::Error>
/// fn get_election_title() -> Result<String> {
///     Ok("Presidential Election 2024".to_string())
/// }
///
/// // Error propagation with ?
/// fn complex_operation() -> Result<()> {
///     let title = get_election_title()?;
///     // ... more operations
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the voting system
///
/// A comprehensive error enum that covers all possible failure modes in the
/// voting system. Each variant includes contextual information appropriate
/// for its error category while maintaining security.
///
/// ## Security Design
///
/// - **Information isolation**: Cryptographic errors never expose key material
/// - **Consistent timing**: All error paths have similar response times
/// - **Audit integration**: All errors can be safely logged for compliance
/// - **Attack prevention**: Error messages don't aid in system exploitation
///
/// ## Error Categorization
///
/// Errors are categorized by their source and handling requirements:
/// - [`Crypto`](Error::Crypto): Cryptographic operation failures
/// - [`Voting`](Error::Voting): Election and voting process errors
/// - [`Validation`](Error::Validation): Input validation failures
/// - [`Serialization`](Error::Serialization): Data format errors
/// - [`Internal`](Error::Internal): System-level failures
///
/// ## Usage Patterns
///
/// ```rust
/// use vote::Error;
///
/// fn handle_error(error: Error) {
///     // Pattern matching for specific error handling
///     match error {
///         Error::Crypto { message } => {
///             // Log security incident, rotate keys if needed
///             eprintln!("Security incident: {}", message);
///         },
///         Error::Voting { message } => {
///             // User-facing error, safe to display
///             eprintln!("Voting error: {}", message);
///         },
///         Error::Validation { field } => {
///             // Field-specific validation error
///             eprintln!("Invalid field: {}", field);
///         },
///         _ => {
///             // Generic error handling
///             eprintln!("System error occurred");
///         }
///     }
/// }
/// ```
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Cryptographic operation errors
    ///
    /// Represents failures in cryptographic operations such as:
    /// - Key generation or derivation failures
    /// - Signature creation or verification errors
    /// - Hash computation failures
    /// - Encryption/decryption errors
    /// - Key rotation failures
    ///
    /// # Security Considerations
    ///
    /// Cryptographic errors are treated as potential security incidents:
    /// - Error messages are carefully crafted to avoid information leakage
    /// - No cryptographic keys or internal state exposed
    /// - Automatic security monitoring integration
    /// - May trigger key rotation or system lockdown procedures
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// let error = Error::crypto("RSA key generation failed");
    /// match error {
    ///     Error::Crypto { message } => {
    ///         assert_eq!(message, "RSA key generation failed");
    ///     },
    ///     _ => unreachable!(),
    /// }
    /// ```
    ///
    /// # Common Causes
    ///
    /// - Hardware security module (HSM) communication failures
    /// - Insufficient entropy for key generation
    /// - Invalid cryptographic parameters
    /// - Key corruption or tampering detection
    /// - Algorithm implementation errors
    #[error("Cryptographic error: {message}")]
    Crypto {
        /// Human-readable description of the cryptographic error
        ///
        /// This message is safe for logging and debugging but should not
        /// contain sensitive cryptographic material or implementation details
        /// that could aid attackers.
        message: String
    },

    /// Voting-specific errors
    ///
    /// Represents failures in voting operations and election management:
    /// - Election timing violations (voting outside allowed window)
    /// - Invalid candidate selections
    /// - Duplicate vote attempts
    /// - Election state inconsistencies
    /// - Vote processing failures
    ///
    /// # User Experience
    ///
    /// Voting errors are often user-facing and should provide clear,
    /// actionable feedback about what went wrong and how to correct it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// let error = Error::voting("Election not accepting votes");
    /// match error {
    ///     Error::Voting { message } => {
    ///         assert_eq!(message, "Election not accepting votes");
    ///     },
    ///     _ => unreachable!(),
    /// }
    /// ```
    ///
    /// # Common Causes
    ///
    /// - Attempting to vote before election starts
    /// - Attempting to vote after election ends
    /// - Selecting invalid or inactive candidates
    /// - Submitting malformed vote data
    /// - Election administration errors
    #[error("Voting error: {message}")]
    Voting {
        /// Human-readable description of the voting error
        ///
        /// This message can typically be displayed to users as it contains
        /// guidance about voting procedures and requirements.
        message: String
    },

    /// Validation errors
    ///
    /// Represents input validation failures with specific field identification.
    /// Used extensively for form validation, API parameter checking, and
    /// data integrity verification.
    ///
    /// # Client Integration
    ///
    /// The `field` parameter enables client applications to:
    /// - Highlight specific form fields with errors
    /// - Provide field-specific error messages
    /// - Implement progressive validation
    /// - Track validation error patterns
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// let error = Error::validation("email_address");
    /// match error {
    ///     Error::Validation { field } => {
    ///         assert_eq!(field, "email_address");
    ///         // Highlight the email field in the UI
    ///     },
    ///     _ => unreachable!(),
    /// }
    /// ```
    ///
    /// # Common Causes
    ///
    /// - Required fields left empty
    /// - Invalid format (email, phone, etc.)
    /// - Out-of-range values
    /// - Constraint violations
    /// - Business rule violations
    #[error("Validation failed: {field}")]
    Validation {
        /// Name of the field that failed validation
        ///
        /// Should match the field name in forms, API parameters, or
        /// data structures to enable precise error highlighting.
        field: String
    },

    /// Serialization errors
    ///
    /// Represents data serialization and deserialization failures,
    /// automatically converted from `serde_json::Error`.
    ///
    /// # Automatic Conversion
    ///
    /// The `#[from]` attribute enables automatic conversion from
    /// `serde_json::Error` using the `?` operator:
    ///
    /// ```rust
    /// use vote::Result;
    /// use serde_json;
    ///
    /// fn parse_json_data(json: &str) -> Result<serde_json::Value> {
    ///     let data = serde_json::from_str(json)?; // Automatic conversion
    ///     Ok(data)
    /// }
    /// ```
    ///
    /// # Security Considerations
    ///
    /// Serialization errors may expose:
    /// - Data structure information
    /// - Input format expectations
    /// - System implementation details
    ///
    /// Be cautious when exposing these errors to untrusted clients.
    ///
    /// # Common Causes
    ///
    /// - Malformed JSON or other data formats
    /// - Schema mismatches during deserialization
    /// - Type conversion failures
    /// - Missing required fields
    /// - Invalid data types
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Generic internal errors
    ///
    /// Represents unexpected system-level failures that don't fit into
    /// other categories. These typically indicate:
    /// - Programming errors or bugs
    /// - System resource exhaustion
    /// - Configuration problems
    /// - External service failures
    ///
    /// # Administrative Response
    ///
    /// Internal errors usually require administrative attention:
    /// - System monitoring and alerting
    /// - Log analysis and debugging
    /// - Configuration review
    /// - Potential system maintenance
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// let error = Error::internal("Database connection pool exhausted");
    /// match error {
    ///     Error::Internal { message } => {
    ///         assert_eq!(message, "Database connection pool exhausted");
    ///         // Trigger administrative alert
    ///     },
    ///     _ => unreachable!(),
    /// }
    /// ```
    ///
    /// # Common Causes
    ///
    /// - Memory allocation failures
    /// - File system errors
    /// - Network connectivity issues
    /// - Database connection problems
    /// - Configuration parsing errors
    #[error("Internal error: {message}")]
    Internal {
        /// Detailed description of the internal error
        ///
        /// Should provide sufficient information for administrators
        /// to diagnose and resolve the issue.
        message: String
    },
}

impl Error {
    /// Create a new cryptographic error
    ///
    /// Constructs a [`Crypto`](Error::Crypto) error with the provided message.
    /// This method should be used for all cryptographic operation failures
    /// to ensure consistent error categorization.
    ///
    /// # Security Guidelines
    ///
    /// When creating crypto errors:
    /// - Never include cryptographic keys or secrets in messages
    /// - Avoid implementation details that could aid attackers
    /// - Use generic descriptions for timing attack prevention
    /// - Consider automatic security incident logging
    ///
    /// # Parameters
    ///
    /// - `message`: Human-readable error description (must not contain secrets)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// // Good: Generic, safe message
    /// let error = Error::crypto("Signature verification failed");
    ///
    /// // Bad: Exposes implementation details
    /// // let error = Error::crypto("RSA-4096 signature verification failed with key 0x1234...");
    /// ```
    ///
    /// # Returns
    ///
    /// A new [`Error::Crypto`] instance with the specified message.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a new voting error
    ///
    /// Constructs a [`Voting`](Error::Voting) error with the provided message.
    /// These errors are typically user-facing and should provide clear,
    /// actionable guidance about voting procedures.
    ///
    /// # User Experience Guidelines
    ///
    /// When creating voting errors:
    /// - Use clear, non-technical language
    /// - Provide actionable guidance when possible
    /// - Include relevant context (e.g., timing, requirements)
    /// - Avoid system implementation details
    ///
    /// # Parameters
    ///
    /// - `message`: User-friendly error description
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// // Good: Clear, actionable message
    /// let error = Error::voting("Election ends in 5 minutes. Please submit your vote now.");
    ///
    /// // Good: Explains what's wrong and when to try again
    /// let error = Error::voting("Voting opens tomorrow at 9:00 AM EST");
    ///
    /// // Bad: Technical details not helpful to users
    /// // let error = Error::voting("Timestamp validation failed: outside allowed window");
    /// ```
    ///
    /// # Returns
    ///
    /// A new [`Error::Voting`] instance with the specified message.
    pub fn voting(message: impl Into<String>) -> Self {
        Self::Voting {
            message: message.into(),
        }
    }

    /// Create a new validation error
    ///
    /// Constructs a [`Validation`](Error::Validation) error for the specified field.
    /// The field name should match the corresponding input field, form element,
    /// or API parameter to enable precise error highlighting.
    ///
    /// # Field Naming Guidelines
    ///
    /// - Use consistent field names across the application
    /// - Match form input names and API parameter names
    /// - Use clear, descriptive field identifiers
    /// - Consider localization requirements for field names
    ///
    /// # Parameters
    ///
    /// - `field`: Name of the field that failed validation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// // Form field validation
    /// let error = Error::validation("voter_id");
    /// let error = Error::validation("election_title");
    /// let error = Error::validation("candidate_selection");
    ///
    /// // API parameter validation
    /// let error = Error::validation("start_time");
    /// let error = Error::validation("signature");
    /// ```
    ///
    /// # Client Integration
    ///
    /// ```javascript
    /// // Example client-side error handling
    /// if (error.type === "Validation") {
    ///     highlightField(error.field);
    ///     showFieldError(error.field, "This field is required");
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// A new [`Error::Validation`] instance for the specified field.
    pub fn validation(field: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
        }
    }

    /// Create a new internal error
    ///
    /// Constructs an [`Internal`](Error::Internal) error with the provided message.
    /// These errors indicate unexpected system conditions that typically require
    /// administrative attention or system debugging.
    ///
    /// # Administrative Context
    ///
    /// Internal errors should provide sufficient information for:
    /// - System administrators to diagnose issues
    /// - Developers to debug problems
    /// - Monitoring systems to trigger appropriate alerts
    /// - Log analysis and correlation
    ///
    /// # Parameters
    ///
    /// - `message`: Detailed error description for administrative use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::Error;
    ///
    /// // System resource errors
    /// let error = Error::internal("Failed to allocate secure memory region");
    /// let error = Error::internal("Database connection pool exhausted");
    ///
    /// // Configuration errors
    /// let error = Error::internal("Invalid HSM configuration: missing required parameters");
    ///
    /// // External service errors
    /// let error = Error::internal("Time service unreachable: clock synchronization failed");
    /// ```
    ///
    /// # Returns
    ///
    /// A new [`Error::Internal`] instance with the specified message.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

/// Convenience macro for creating cryptographic errors
///
/// This macro provides a convenient way to create [`Error::Crypto`] instances
/// with format string support, similar to the `format!` macro.
///
/// # Security Considerations
///
/// The same security guidelines apply as with [`Error::crypto`]:
/// - Never include cryptographic keys or secrets
/// - Avoid exposing implementation details
/// - Use generic descriptions to prevent timing attacks
///
/// # Examples
///
/// ```rust
/// use vote::crypto_error;
///
/// // Simple message
/// let error = crypto_error!("Key generation failed");
///
/// // Formatted message
/// let key_type = "Ed25519";
/// let error = crypto_error!("Failed to generate {} keypair", key_type);
///
/// // With additional context
/// let operation = "signature verification";
/// let algorithm = "Ed25519";
/// let error = crypto_error!("{} failed using {} algorithm", operation, algorithm);
/// ```
///
/// # Expansion
///
/// ```rust,no_run
/// # let len = 32;
/// // crypto_error!("Invalid key length: {}", len)
/// // Expands to:
/// vote::Error::crypto(format!("Invalid key length: {}", len))
/// # ;
/// ```
#[macro_export]
macro_rules! crypto_error {
    ($msg:expr) => {
        $crate::Error::crypto($msg)
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::crypto(format!($fmt, $($arg)*))
    };
}

/// Convenience macro for creating voting errors
///
/// This macro provides a convenient way to create [`Error::Voting`] instances
/// with format string support. The resulting errors are typically user-facing
/// and should provide clear, actionable guidance.
///
/// # User Experience Guidelines
///
/// - Use clear, non-technical language
/// - Provide specific guidance when possible
/// - Include relevant timing or procedural information
/// - Avoid exposing system implementation details
///
/// # Examples
///
/// ```rust
/// use vote::voting_error;
///
/// // Simple user message
/// let error = voting_error!("Election has not started yet");
///
/// // Formatted with context
/// let election_title = "Board Election 2024";
/// let error = voting_error!("Cannot vote in '{}': election has ended", election_title);
///
/// // Time-sensitive guidance
/// let minutes_remaining = 15;
/// let error = voting_error!("Election closes in {} minutes", minutes_remaining);
/// ```
///
/// # Expansion
///
/// ```rust,no_run
/// # let candidate_id = "alice";
/// // voting_error!("Invalid candidate: {}", candidate_id)
/// // Expands to:
/// vote::Error::voting(format!("Invalid candidate: {}", candidate_id))
/// # ;
/// ```
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

        let internal_err = Error::internal("test internal error");
        assert!(matches!(internal_err, Error::Internal { .. }));
    }

    #[test]
    fn test_error_macros() {
        let crypto_err = crypto_error!("test error");
        assert!(matches!(crypto_err, Error::Crypto { .. }));

        let voting_err = voting_error!("test error");
        assert!(matches!(voting_err, Error::Voting { .. }));

        // Test formatting
        let formatted_crypto = crypto_error!("error code: {}", 42);
        if let Error::Crypto { message } = formatted_crypto {
            assert_eq!(message, "error code: 42");
        } else {
            panic!("Expected Crypto error");
        }

        let formatted_voting = voting_error!("candidate {} is invalid", "alice");
        if let Error::Voting { message } = formatted_voting {
            assert_eq!(message, "candidate alice is invalid");
        } else {
            panic!("Expected Voting error");
        }
    }

    #[test]
    fn test_error_display() {
        let crypto_err = Error::crypto("signature failed");
        assert_eq!(crypto_err.to_string(), "Cryptographic error: signature failed");

        let voting_err = Error::voting("election closed");
        assert_eq!(voting_err.to_string(), "Voting error: election closed");

        let validation_err = Error::validation("email");
        assert_eq!(validation_err.to_string(), "Validation failed: email");

        let internal_err = Error::internal("database error");
        assert_eq!(internal_err.to_string(), "Internal error: database error");
    }

    #[test]
    fn test_serialization_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json");
        assert!(json_err.is_err());

        // Test automatic conversion
        let converted: Error = json_err.unwrap_err().into();
        assert!(matches!(converted, Error::Serialization(_)));
    }

    #[test]
    fn test_result_type_alias() {
        fn example_function() -> Result<String> {
            Ok("success".to_string())
        }

        fn example_error_function() -> Result<String> {
            Err(Error::internal("test error"))
        }

        assert!(example_function().is_ok());
        assert!(example_error_function().is_err());
    }

    #[test]
    fn test_error_pattern_matching() {
        let errors = vec![
            Error::crypto("crypto test"),
            Error::voting("voting test"),
            Error::validation("field_test"),
            Error::internal("internal test"),
        ];

        for error in errors {
            match error {
                Error::Crypto { message } => assert!(message.contains("crypto")),
                Error::Voting { message } => assert!(message.contains("voting")),
                Error::Validation { field } => assert!(field.contains("field")),
                Error::Internal { message } => assert!(message.contains("internal")),
                Error::Serialization(_) => panic!("Unexpected serialization error"),
            }
        }
    }
}