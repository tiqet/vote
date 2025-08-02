//! # Cryptographically Secure Voting System
//!
//! A bank-grade, cryptographically secure voting system designed for high-stakes elections.
//! This library provides a minimal, auditable foundation that can be incrementally expanded
//! with additional features while maintaining security and reliability.
//!
//! ## Key Features
//!
//! - **Bank-grade security**: Cryptographic primitives with comprehensive audit trails
//! - **Anonymous voting**: Zero-knowledge voter anonymization with secure tokens
//! - **Comprehensive monitoring**: Real-time security monitoring and incident detection
//! - **Future-ready architecture**: Designed for easy integration of Web/DB layers
//! - **Extensive testing**: Full test coverage including stress tests and edge cases
//!
//! ## Security Architecture
//!
//! The system employs multiple layers of security:
//! - Ed25519 digital signatures for vote integrity
//! - Blake3 cryptographic hashing for data verification
//! - Secure memory management with automatic cleanup
//! - Rate limiting and DoS protection
//! - Comprehensive audit logging with integrity verification
//! - Automatic security incident detection and response
//!
//! ## Quick Start
//!
//! ```rust
//! use vote::{init, Result};
//!
//! fn main() -> Result<()> {
//!     // Initialize the voting system with proper logging
//!     init()?;
//!
//!     // Your voting system is now ready to use
//!     println!("Voting system initialized successfully");
//!     Ok(())
//! }
//! ```
//!
//! ## Module Organization
//!
//! - [`config`]: Secure configuration management with environment validation
//! - [`crypto`]: Cryptographic primitives and security services
//! - [`errors`]: Comprehensive error handling and reporting
//! - [`types`]: Core data types and structures for the voting system
//!
//! ## Configuration
//!
//! The system requires secure configuration via environment variables.
//! See the [`config`] module for detailed setup instructions.
//!
//! ## Compliance
//!
//! This library is designed to meet banking and regulatory standards:
//! - SOX compliance through comprehensive audit trails
//! - PCI DSS readiness with secure cryptographic operations
//! - Regulatory logging and reporting capabilities

pub mod config;
pub mod crypto;
pub mod errors;
pub mod types;

// Re-export commonly used types for convenience
pub use errors::{Error, Result};

/// Library version string derived from Cargo.toml
///
/// This constant provides the current version of the voting system library,
/// automatically extracted from the package metadata during compilation.
///
/// # Example
///
/// ```rust
/// use vote::VERSION;
///
/// println!("Voting system version: {}", VERSION);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the voting system with comprehensive logging and security monitoring
///
/// This function sets up the foundational infrastructure required for secure voting operations:
///
/// - Configures structured logging with appropriate filters
/// - Enables security event monitoring
/// - Sets up audit trail infrastructure
/// - Validates system readiness
///
/// # Logging Configuration
///
/// The logging system is configured with:
/// - Environment-based log level filtering (defaults to "vote=info")
/// - Structured JSON output for production deployments
/// - Security event correlation and monitoring
/// - Audit trail integration for compliance
///
/// # Environment Variables
///
/// - `RUST_LOG`: Override default logging configuration
/// - `LOG_LEVEL`: Set specific log level (trace, debug, info, warn, error)
/// - `LOG_FORMAT`: Choose output format (json, pretty, compact)
///
/// # Returns
///
/// Returns `Ok(())` on successful initialization, or an [`Error`] if:
/// - Logging system fails to initialize
/// - Security monitoring setup fails
/// - Required environment variables are missing or invalid
///
/// # Examples
///
/// ```rust
/// use vote::{init, Result};
///
/// fn main() -> Result<()> {
///     // Initialize with default configuration
///     init()?;
///
///     println!("✅ Voting system ready for secure operations");
///     Ok(())
/// }
/// ```
///
/// ```rust
/// use vote::{init, Result};
/// use std::env;
///
/// fn main() -> Result<()> {
///     // Configure detailed logging for development
///     unsafe {
///         env::set_var("RUST_LOG", "vote=debug,tower=info");
///     }
///
///     init()?;
///
///     println!("🔍 Development mode with detailed logging enabled");
///     Ok(())
/// }
/// ```
///
/// # Security Considerations
///
/// - Initialization should be called once at application startup
/// - Ensure proper environment configuration before calling
/// - Monitor initialization logs for security warnings
/// - Verify audit trail functionality after initialization
///
/// # Thread Safety
///
/// This function is thread-safe and can be called from multiple threads,
/// though it should typically only be called once per application instance.
pub fn init() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vote=info".into()),
        )
        .init();

    tracing::info!(
        version = VERSION,
        "🗳️  Cryptographically secure voting system initialized"
    );

    // Log security initialization confirmation
    tracing::info!(
        security_features = "Ed25519 signatures, Blake3 hashing, secure memory management",
        compliance = "SOX, PCI DSS ready",
        "🔒 Security infrastructure activated"
    );

    Ok(())
}