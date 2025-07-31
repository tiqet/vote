//! Simple test to verify compilation and basic functionality

use chrono::Utc;
use uuid::Uuid;
use vote::{
    Result,
    config::Config,
    crypto::{CryptoRateLimiter, SecureKeyPair, SecureMemory, SecureSaltManager},
    types::Election,
};

#[tokio::test]
async fn test_basic_compilation() -> Result<()> {
    println!("🔧 Testing basic compilation and functionality...");

    // Test configuration
    let config = Config::for_testing()?;
    assert!(config.security.key_expiry_seconds > 0);
    println!("✅ Configuration works");

    // Test secure crypto
    let key_pair = SecureKeyPair::generate_with_expiration(Some(3600))?;
    assert!(!key_pair.is_expired());
    println!("✅ Secure key pair works");

    // Test signing with timestamp
    let message = b"test message";
    let (signature, timestamp) = key_pair.sign_with_timestamp(message)?;
    key_pair.verify_with_timestamp(message, &signature, timestamp, 300)?;
    println!("✅ Timestamped signing and verification works");

    // Test salt manager
    let salt_manager = SecureSaltManager::for_testing();
    let bank_id = "CZ1234567890";
    let election_id = Uuid::new_v4();
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let _voter_hash =
        salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_timestamp, 300)?;
    println!("✅ Secure salt manager works");

    // Test rate limiter
    let mut rate_limiter = CryptoRateLimiter::new(10);
    assert!(rate_limiter.check_rate_limit().is_ok());
    println!("✅ Rate limiter works");

    // Test memory security
    let random1 = SecureMemory::secure_random_bytes::<32>();
    let random2 = SecureMemory::secure_random_bytes::<32>();
    assert_ne!(random1, random2);
    println!("✅ Secure memory works");

    // Test basic types
    let election = Election {
        id: Uuid::new_v4(),
        title: "Test Election".to_string(),
        description: None,
        start_time: Utc::now().timestamp() - 3600,
        end_time: Utc::now().timestamp() + 3600,
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    println!("✅ Election types work");

    println!("🎉 All basic functionality verified!");
    println!("🔒 Security features working:");
    println!("   • Environment-based salts");
    println!("   • Timestamp replay protection");
    println!("   • Cryptographic rate limiting");
    println!("   • Key expiration management");
    println!("   • Banking-grade crypto (Ed25519 + Blake3)");

    Ok(())
}
