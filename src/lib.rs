//! Cryptographically Secure Voting System
//!
//! A minimal foundation that will be expanded incrementally.

pub mod config;
pub mod crypto;
pub mod errors;
pub mod types;

// Re-export commonly used types
pub use errors::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the voting system with proper logging
pub fn init() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vote=info".into()),
        )
        .init();

    tracing::info!("🗳️  Voting system v{} initialized", VERSION);
    Ok(())
}
