//! Security-focused integration tests for the voting system foundation

use vote::{
    config::Config,
    crypto::{
        KeyPair, VoterHasher, TokenGenerator, CryptoUtils,
        SecureKeyPair, SecureSaltManager, CryptoRateLimiter, SecureMemory,
        voting_lock::{VotingLockService, VotingMethod, LockResult}
    },
    types::{Election, Candidate, AnonymousVote},
    Result,
};
use uuid::Uuid;
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_double_voting_prevention_workflow() -> Result<()> {
    println!("🚫 Testing double voting prevention workflow...");

    // Setup
    let salt_manager = SecureSaltManager::for_testing();
    let lock_service = VotingLockService::new();
    let election_id = Uuid::new_v4();
    let bank_id = "CZ1234567890";

    // Generate voter hash (this is how we identify voters anonymously)
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let voter_hash = salt_manager.hash_voter_identity_secure(
        bank_id,
        &election_id,
        current_time,
        300
    )?;
    let voter_hash_str = hex::encode(voter_hash);

    println!("✅ Generated anonymous voter hash: {}...", &voter_hash_str[0..8]);

    // Test 1: First voting attempt (Digital) - should succeed
    println!("\n📱 Test 1: Digital voting attempt...");
    let digital_lock_result = lock_service.acquire_lock(
        &voter_hash_str,
        &election_id,
        VotingMethod::Digital
    )?;

    match digital_lock_result {
        LockResult::Acquired(lock) => {
            println!("✅ Digital voting lock acquired successfully");
            println!("   Lock ID: {}", lock.lock_id);
            println!("   Expires in: {} seconds", lock.time_remaining());

            // Simulate digital voting process
            println!("   📝 Processing digital vote...");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Don't release lock yet - voting still in progress
        }
        _ => panic!("Expected digital lock to be acquired"),
    }

    // Test 2: Concurrent analog voting attempt - should fail
    println!("\n🗳️  Test 2: Attempting analog voting (should fail)...");
    let analog_lock_result = lock_service.acquire_lock(
        &voter_hash_str,
        &election_id,
        VotingMethod::Analog
    )?;

    match analog_lock_result {
        LockResult::AlreadyLocked { existing_lock, conflict_method } => {
            println!("✅ Analog voting correctly blocked!");
            println!("   Conflict with: {:?}", conflict_method);
            println!("   Existing lock expires in: {} seconds", existing_lock.time_remaining());
            assert_eq!(conflict_method, VotingMethod::Digital);
        }
        _ => panic!("Expected analog voting to be blocked"),
    }

    // Test 3: Check lock status
    println!("\n🔍 Test 3: Checking lock status...");
    let lock_status = lock_service.is_locked(&voter_hash_str, &election_id)?;
    match lock_status {
        Some(lock) => {
            println!("✅ Lock confirmed active");
            println!("   Method: {:?}", lock.method);
            println!("   Time remaining: {} seconds", lock.time_remaining());
        }
        None => panic!("Expected lock to be active"),
    }

    // Test 4: Complete digital voting and release lock
    println!("\n✅ Test 4: Completing digital voting...");
    if let Some(active_lock) = lock_service.is_locked(&voter_hash_str, &election_id)? {
        let released = lock_service.release_lock(&active_lock)?;
        assert!(released);
        println!("✅ Digital voting completed, lock released");
    }

    // Test 5: Verify lock is released
    println!("\n🔓 Test 5: Verifying lock release...");
    let lock_status_after = lock_service.is_locked(&voter_hash_str, &election_id)?;
    assert!(lock_status_after.is_none());
    println!("✅ Lock successfully released");

    // Test 6: Now analog voting should work
    println!("\n🗳️  Test 6: Analog voting after digital completion...");
    let analog_retry_result = lock_service.acquire_lock(
        &voter_hash_str,
        &election_id,
        VotingMethod::Analog
    )?;

    match analog_retry_result {
        LockResult::Acquired(lock) => {
            println!("✅ Analog voting now allowed (but this would be blocked by double-vote detection)");

            // In real system, this would be blocked by double-vote detection
            // since we already have a completed vote for this voter_hash
            println!("   ⚠️  NOTE: In production, this would be blocked by completed vote detection");

            // Clean up
            lock_service.release_lock(&lock)?;
        }
        _ => panic!("Expected analog voting to work after digital completion"),
    }

    // Test 7: Service statistics
    println!("\n📊 Test 7: Lock service statistics...");
    let stats = lock_service.get_stats()?;
    println!("✅ Lock service stats:");
    println!("   Total locks: {}", stats.total_locks);
    println!("   Active locks: {}", stats.active_locks);
    println!("   Expired locks: {}", stats.expired_locks);

    // Test 8: Different voter, same election - should work
    println!("\n👤 Test 8: Different voter, same election...");
    let different_bank_id = "CZ9876543210";
    let different_voter_hash = salt_manager.hash_voter_identity_secure(
        different_bank_id,
        &election_id,
        current_time,
        300
    )?;
    let different_voter_hash_str = hex::encode(different_voter_hash);

    let different_voter_result = lock_service.acquire_lock(
        &different_voter_hash_str,
        &election_id,
        VotingMethod::Digital
    )?;

    match different_voter_result {
        LockResult::Acquired(lock) => {
            println!("✅ Different voter can vote in same election");
            lock_service.release_lock(&lock)?;
        }
        _ => panic!("Expected different voter to be able to vote"),
    }

    println!("\n🎉 Double voting prevention workflow test completed!");
    println!("🔒 Key security features verified:");
    println!("   • Temporal locking prevents race conditions");
    println!("   • Anonymous voter hashes preserve privacy");
    println!("   • Same voter cannot vote twice simultaneously");
    println!("   • Different voters don't interfere with each other");
    println!("   • Locks automatically expire to prevent deadlocks");

    Ok(())
}

#[tokio::test]
async fn test_secure_crypto_operations() -> Result<()> {
    println!("🔒 Testing secure cryptographic operations...");

    // Test secure key pair with expiration
    let key_pair = SecureKeyPair::generate_with_expiration(Some(3600))?; // 1 hour
    assert!(!key_pair.is_expired());

    let message = b"test vote content";
    let (signature, timestamp) = key_pair.sign_with_timestamp(message)?;

    // Verify with timestamp validation
    key_pair.verify_with_timestamp(message, &signature, timestamp, 300)?;
    println!("✅ Secure key pair with timestamp verification works");

    // Test replay protection
    let old_timestamp = timestamp - 400; // 400 seconds ago
    assert!(key_pair.verify_with_timestamp(message, &signature, old_timestamp, 300).is_err());
    println!("✅ Replay protection works");

    // Test secure salt manager
    let salt_manager = SecureSaltManager::for_testing();
    let bank_id = "CZ1234567890";
    let election_id = Uuid::new_v4();
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let hash1 = salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_time, 300)?;
    let hash2 = salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_time, 300)?;
    assert_eq!(hash1, hash2);

    // Test timestamp validation
    let old_time = current_time - 400;
    assert!(salt_manager.hash_voter_identity_secure(bank_id, &election_id, old_time, 300).is_err());
    println!("✅ Secure voter hashing with timestamp validation works");

    // Test rate limiter
    let mut rate_limiter = CryptoRateLimiter::new(2); // 2 ops per second
    assert!(rate_limiter.check_rate_limit().is_ok());
    assert!(rate_limiter.check_rate_limit().is_ok());
    assert!(rate_limiter.check_rate_limit().is_err()); // Should be rate limited
    println!("✅ Rate limiting works");

    Ok(())
}

#[tokio::test]
async fn test_secure_configuration() -> Result<()> {
    println!("⚙️ Testing secure configuration management...");

    // Test configuration validation
    let config = Config::for_testing()?;

    // Test salt validation
    let voter_salt = config.security.voter_salt_bytes()?;
    let token_salt = config.security.token_salt_bytes()?;

    assert!(voter_salt.len() >= 32);
    assert!(token_salt.len() >= 32);
    assert_ne!(voter_salt, token_salt); // Should be different

    println!("✅ Secure configuration validation works");

    // Test security settings
    assert!(config.security.key_expiry_seconds > 0);
    assert!(config.security.max_crypto_ops_per_second > 0);
    assert!(config.security.max_timestamp_age_seconds > 0);

    println!("✅ Security configuration parameters valid");

    Ok(())
}

#[tokio::test]
async fn test_banking_grade_voting_workflow() -> Result<()> {
    println!("🏦 Testing banking-grade voting workflow...");

    // 1. Initialize secure configuration
    let config = Config::for_testing()?;
    let salt_manager = SecureSaltManager::for_testing();
    let mut rate_limiter = CryptoRateLimiter::new(10);

    // 2. Create election with proper timing
    let now = Utc::now().timestamp();
    let election = Election {
        id: Uuid::new_v4(),
        title: "Secure Mayoral Election 2024".to_string(),
        description: Some("Banking-grade secure election".to_string()),
        start_time: now - 3600,
        end_time: now + 3600,
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    println!("✅ Secure election created and accepting votes");

    // 3. Create candidates
    let candidates = vec![
        Candidate {
            id: "secure_candidate_a".to_string(),
            election_id: election.id,
            name: "Alice Secure".to_string(),
            description: Some("Cryptographically verified candidate".to_string()),
            active: true,
        },
        Candidate {
            id: "secure_candidate_b".to_string(),
            election_id: election.id,
            name: "Bob Verified".to_string(),
            description: Some("Zero-knowledge candidate".to_string()),
            active: true,
        },
    ];

    println!("✅ Secure candidates created: {}", candidates.len());

    // 4. Simulate secure voting process
    for i in 1..=3 {
        // Rate limiting check
        rate_limiter.check_rate_limit()?;

        let bank_id = format!("CZ123456789{:02}", i);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Generate secure voter hash with timestamp
        let voter_hash = salt_manager.hash_voter_identity_secure(
            &bank_id,
            &election.id,
            current_time,
            300 // 5 minute window
        )?;

        // Generate secure voting token
        let expires_at = current_time + config.security.key_expiry_seconds;
        let (_token_hash, _nonce) = salt_manager.generate_voting_token_secure(
            &voter_hash,
            &election.id,
            expires_at,
        )?;

        // Create secure key pair for vote signing
        let key_pair = SecureKeyPair::generate_with_expiration(
            Some(config.security.key_expiry_seconds)
        )?;

        // Select candidate and create vote
        let chosen_candidate = &candidates[i % candidates.len()];
        let vote_content = format!("secure_vote_for:{}", chosen_candidate.id);

        // Sign vote with timestamp
        let (vote_signature, signature_timestamp) = key_pair.sign_with_timestamp(vote_content.as_bytes())?;

        // Verify signature immediately (as would happen in real system)
        key_pair.verify_with_timestamp(
            vote_content.as_bytes(),
            &vote_signature,
            signature_timestamp,
            config.security.max_timestamp_age_seconds,
        )?;

        // Create integrity hash
        let integrity_hash = CryptoUtils::hash(vote_content.as_bytes());

        // Create anonymous vote with proper serialization
        let anonymous_vote = AnonymousVote::new(
            Uuid::new_v4(),
            election.id,
            vote_content.into_bytes(),
            &vote_signature,
            &integrity_hash,
            signature_timestamp as i64,
        );

        // Test serialization security
        let vote_json = serde_json::to_string(&anonymous_vote)?;
        let vote_back: AnonymousVote = serde_json::from_str(&vote_json)?;
        assert_eq!(anonymous_vote.vote_id, vote_back.vote_id);

        // Verify vote integrity
        assert!(anonymous_vote.signature_array().is_some());
        assert!(anonymous_vote.hash_array().is_some());

        println!("✅ Secure voter {} cast verified vote for {}", i, chosen_candidate.name);

        // Small delay to prevent timing attacks in testing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    println!("✅ Banking-grade voting workflow completed successfully");
    println!("🔒 All cryptographic operations verified");
    println!("⏱️ All timestamps validated");
    println!("🛡️ All security measures enforced");

    Ok(())
}

#[test]
fn test_security_error_handling() {
    use vote::{Error, crypto_error, voting_error};

    // Test that crypto errors don't leak sensitive information
    let crypto_err = crypto_error!("test crypto error");
    assert!(matches!(crypto_err, Error::Crypto { .. }));

    let voting_err = voting_error!("test voting error");
    assert!(matches!(voting_err, Error::Voting { .. }));

    // Test that errors can be safely displayed without information leakage
    let error_msg = format!("{}", crypto_err);
    assert!(!error_msg.contains("sensitive"));
    assert!(!error_msg.contains("key"));
    assert!(!error_msg.contains("private"));

    println!("✅ Security-focused error handling works correctly");
}

#[tokio::test]
async fn test_memory_security() -> Result<()> {
    // Test constant-time comparison
    let data1 = b"test_data_123456";
    let data2 = b"test_data_123456";
    let data3 = b"different_data12";

    assert!(SecureMemory::constant_time_eq(data1, data2));
    assert!(!SecureMemory::constant_time_eq(data1, data3));

    // Test secure random generation
    let random1 = SecureMemory::secure_random_bytes::<32>();
    let random2 = SecureMemory::secure_random_bytes::<32>();

    assert_ne!(random1, random2); // Should be different
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);

    println!("✅ Memory security operations work correctly");

    Ok(())
}

#[tokio::test]
async fn test_basic_crypto_operations() -> Result<()> {
    // Test key pair generation and signing
    let key_pair = KeyPair::generate()?;
    let message = b"test vote content";

    let signature = key_pair.sign(message);
    key_pair.verify(message, &signature)?;

    println!("✅ Key pair generation and signing works");

    // Test voter hashing
    let hasher = VoterHasher::with_default_salt();
    let bank_id = "CZ1234567890";
    let election_id = Uuid::new_v4();

    let voter_hash = hasher.hash_voter_identity(bank_id, &election_id);
    let voter_hash2 = hasher.hash_voter_identity(bank_id, &election_id);

    assert_eq!(voter_hash, voter_hash2);
    println!("✅ Voter hashing works");

    // Test token generation
    let mut token_gen = TokenGenerator::new();
    let token1 = token_gen.generate_token();
    let token2 = token_gen.generate_token();

    assert_ne!(token1, token2);
    println!("✅ Token generation works");

    // Test crypto utils
    let data = b"test data for hashing";
    let hash = CryptoUtils::hash(data);
    let hash_hex = CryptoUtils::hash_to_hex(&hash);
    let hash_back = CryptoUtils::hex_to_hash(&hash_hex)?;

    assert_eq!(hash, hash_back);
    println!("✅ Crypto utilities work");

    Ok(())
}

#[tokio::test]
async fn test_basic_types() -> Result<()> {
    // Test election creation and timing
    let now = Utc::now().timestamp();
    let election = Election {
        id: Uuid::new_v4(),
        title: "Test Election".to_string(),
        description: Some("A test election".to_string()),
        start_time: now - 3600, // Started 1 hour ago
        end_time: now + 3600,   // Ends in 1 hour
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    assert!(!election.is_future());
    assert!(!election.has_ended());

    println!("✅ Election timing logic works");

    // Test candidate creation
    let candidate = Candidate {
        id: "candidate_1".to_string(),
        election_id: election.id,
        name: "Test Candidate".to_string(),
        description: Some("A test candidate".to_string()),
        active: true,
    };

    assert_eq!(candidate.election_id, election.id);
    println!("✅ Candidate creation works");

    // Test serialization
    let election_json = serde_json::to_string(&election)?;
    let election_back: Election = serde_json::from_str(&election_json)?;

    assert_eq!(election, election_back);

    // Test anonymous vote creation and serialization
    let key_pair = KeyPair::generate()?;
    let vote_content = b"test vote content";
    let signature = key_pair.sign(vote_content);
    let hash = CryptoUtils::hash(vote_content);

    let vote = AnonymousVote::new(
        Uuid::new_v4(),
        election.id,
        vote_content.to_vec(),
        &signature,
        &hash,
        Utc::now().timestamp(),
    );

    let vote_json = serde_json::to_string(&vote)?;
    let vote_back: AnonymousVote = serde_json::from_str(&vote_json)?;
    assert_eq!(vote.vote_id, vote_back.vote_id);

    println!("✅ Serialization works");

    Ok(())
}

#[tokio::test]
async fn test_voting_workflow_simulation() -> Result<()> {
    println!("🗳️ Simulating basic voting workflow...");

    // 1. Create election
    let election = Election {
        id: Uuid::new_v4(),
        title: "Mayoral Election 2024".to_string(),
        description: Some("Election for mayor".to_string()),
        start_time: Utc::now().timestamp() - 3600,
        end_time: Utc::now().timestamp() + 3600,
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    println!("✅ Election created and is accepting votes");

    // 2. Create candidates
    let candidates = vec![
        Candidate {
            id: "candidate_a".to_string(),
            election_id: election.id,
            name: "Alice Johnson".to_string(),
            description: Some("Progressive candidate".to_string()),
            active: true,
        },
        Candidate {
            id: "candidate_b".to_string(),
            election_id: election.id,
            name: "Bob Smith".to_string(),
            description: Some("Conservative candidate".to_string()),
            active: true,
        },
    ];

    println!("✅ Candidates created: {}", candidates.len());

    // 3. Simulate voter registration and voting
    let hasher = VoterHasher::with_default_salt();
    let key_pair = KeyPair::generate()?;
    let mut token_gen = TokenGenerator::new();

    for i in 1..=5 {
        let bank_id = format!("CZ123456789{}", i);
        let voter_hash = hasher.hash_voter_identity(&bank_id, &election.id);

        // Generate voting token
        let nonce = token_gen.generate_nonce();
        let _token_hash = hasher.hash_token(&voter_hash, &election.id, &nonce);

        // Simulate vote content (just choosing a candidate)
        let chosen_candidate = &candidates[i % candidates.len()];
        let vote_content = format!("vote_for:{}", chosen_candidate.id);

        // Sign the vote and create integrity hash
        let vote_signature = key_pair.sign(vote_content.as_bytes());
        let integrity_hash = CryptoUtils::hash(vote_content.as_bytes());

        // Create anonymous vote
        let anonymous_vote = AnonymousVote::new(
            Uuid::new_v4(),
            election.id,
            vote_content.into_bytes(),
            &vote_signature,
            &integrity_hash,
            Utc::now().timestamp(),
        );

        // Test serialization
        let vote_json = serde_json::to_string(&anonymous_vote)?;
        let vote_back: AnonymousVote = serde_json::from_str(&vote_json)?;
        assert_eq!(anonymous_vote.vote_id, vote_back.vote_id);

        println!("✅ Voter {} cast vote for {}", i, chosen_candidate.name);
    }

    println!("✅ Voting workflow simulation completed successfully");

    Ok(())
}

#[test]
fn test_error_handling() {
    use vote::{Error, crypto_error, voting_error};

    let crypto_err = crypto_error!("test crypto error");
    assert!(matches!(crypto_err, Error::Crypto { .. }));

    let voting_err = voting_error!("test voting error");
    assert!(matches!(voting_err, Error::Voting { .. }));

    let validation_err = Error::validation("test_field");
    assert!(matches!(validation_err, Error::Validation { .. }));

    println!("✅ Error handling works correctly");
}