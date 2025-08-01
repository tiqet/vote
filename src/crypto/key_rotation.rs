//! Automatic cryptographic key rotation system
//!
//! This module provides automatic key rotation with overlap periods to ensure
//! zero-downtime operation. Keys are rotated before they expire, with both
//! current and previous keys remaining valid during the overlap period.
//!
//! Key features:
//! - Automatic rotation before expiration
//! - Overlap periods for graceful transitions  
//! - Fallback verification with previous keys
//! - Integration with existing SecureKeyPair system
//! - Comprehensive monitoring and logging

use crate::crypto::SecureKeyPair;
use crate::{Result, crypto_error};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Configuration for key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    /// How often to rotate keys (in seconds)
    pub rotation_interval: u64,
    /// Overlap period where both old and new keys are valid (in seconds)
    pub overlap_period: u64,
    /// How often to check if rotation is needed (in seconds)
    pub check_interval: u64,
    /// Maximum number of previous keys to keep for verification
    pub max_previous_keys: usize,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: 86400, // 24 hours
            overlap_period: 3600,     // 1 hour overlap
            check_interval: 3600,     // Check every hour
            max_previous_keys: 3,     // Keep 3 previous keys
        }
    }
}

impl KeyRotationConfig {
    /// Create configuration for testing with shorter intervals
    pub fn for_testing() -> Self {
        Self {
            rotation_interval: 300, // 5 minutes
            overlap_period: 60,     // 1 minute overlap
            check_interval: 30,     // Check every 30 seconds
            max_previous_keys: 2,   // Keep 2 previous keys
        }
    }

    /// Validate configuration parameters
    pub fn validate(&self) -> Result<()> {
        if self.overlap_period >= self.rotation_interval {
            return Err(crypto_error!(
                "Overlap period must be less than rotation interval"
            ));
        }

        if self.check_interval > self.rotation_interval / 2 {
            return Err(crypto_error!(
                "Check interval should be much smaller than rotation interval"
            ));
        }

        if self.max_previous_keys == 0 {
            return Err(crypto_error!("Must keep at least 1 previous key"));
        }

        if self.max_previous_keys > 10 {
            return Err(crypto_error!("Too many previous keys - maximum 10 allowed"));
        }

        Ok(())
    }
}

/// Metadata about a key rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    pub event_id: Uuid,
    pub timestamp: u64,
    pub event_type: RotationEventType,
    pub old_key_id: Option<Uuid>,
    pub new_key_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationEventType {
    Scheduled, // Normal scheduled rotation
    Emergency, // Emergency rotation (key compromise)
    Manual,    // Manual rotation triggered by admin
    Startup,   // Initial key generation at startup
}

/// Key with metadata for rotation management
#[derive(Debug, Clone)]
struct ManagedKey {
    key: SecureKeyPair,
    key_id: Uuid,
    created_at: u64,
    expires_at: u64,
    rotation_due_at: u64, // When rotation should happen (before expiration)
}

impl ManagedKey {
    fn new(key: SecureKeyPair, rotation_interval: u64, overlap_period: u64) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        let expires_at = now + rotation_interval + overlap_period;
        let rotation_due_at = now + rotation_interval;

        Ok(Self {
            key,
            key_id: Uuid::new_v4(),
            created_at: now,
            expires_at,
            rotation_due_at,
        })
    }

    fn is_rotation_due(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now >= self.rotation_due_at
    }

    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now >= self.expires_at
    }

    fn time_until_rotation(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.rotation_due_at.saturating_sub(now)
    }
}

/// Statistics about the key rotation system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationStats {
    pub current_key_id: Uuid,
    pub current_key_age_seconds: u64,
    pub time_until_rotation_seconds: u64,
    pub previous_keys_count: usize,
    pub total_rotations: u64,
    pub last_rotation_timestamp: Option<u64>,
    pub emergency_rotations: u64,
    pub is_healthy: bool,
    pub warnings: Vec<String>,
}

/// Core key rotation manager
pub struct KeyRotationManager {
    config: KeyRotationConfig,
    current_key: Arc<RwLock<ManagedKey>>,
    previous_keys: Arc<RwLock<Vec<ManagedKey>>>,
    rotation_events: Arc<RwLock<Vec<KeyRotationEvent>>>,
    total_rotations: Arc<RwLock<u64>>,
    emergency_rotations: Arc<RwLock<u64>>,
}

impl KeyRotationManager {
    /// Create new key rotation manager with initial key
    pub async fn new(config: KeyRotationConfig) -> Result<Self> {
        config.validate()?;

        // Generate initial key
        let initial_key = SecureKeyPair::generate_with_expiration(Some(
            config.rotation_interval + config.overlap_period,
        ))?;

        let managed_key =
            ManagedKey::new(initial_key, config.rotation_interval, config.overlap_period)?;

        // Log initial key generation
        let startup_event = KeyRotationEvent {
            event_id: Uuid::new_v4(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event_type: RotationEventType::Startup,
            old_key_id: None,
            new_key_id: managed_key.key_id,
            reason: "Initial key generation at startup".to_string(),
        };

        tracing::info!(
            "🔑 Key rotation manager initialized: key_id={}, rotation_interval={}s, overlap={}s",
            managed_key.key_id,
            config.rotation_interval,
            config.overlap_period
        );

        Ok(Self {
            config,
            current_key: Arc::new(RwLock::new(managed_key)),
            previous_keys: Arc::new(RwLock::new(Vec::new())),
            rotation_events: Arc::new(RwLock::new(vec![startup_event])),
            total_rotations: Arc::new(RwLock::new(0)),
            emergency_rotations: Arc::new(RwLock::new(0)),
        })
    }

    /// Create key rotation manager for testing
    pub async fn for_testing() -> Result<Self> {
        Self::new(KeyRotationConfig::for_testing()).await
    }

    /// Check if rotation is needed and perform it if necessary
    pub async fn rotate_if_needed(&self) -> Result<bool> {
        let current = self.current_key.read().await;

        if current.is_rotation_due() {
            let old_key_id = current.key_id;
            drop(current); // Release read lock before rotation

            self.perform_rotation(
                RotationEventType::Scheduled,
                old_key_id,
                "Scheduled rotation due to age",
            )
            .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Force immediate key rotation (for emergency situations)
    pub async fn emergency_rotation(&self, reason: &str) -> Result<()> {
        let old_key_id = {
            let current = self.current_key.read().await;
            current.key_id
        };

        self.perform_rotation(RotationEventType::Emergency, old_key_id, reason)
            .await?;

        let mut emergency_count = self.emergency_rotations.write().await;
        *emergency_count += 1;

        tracing::warn!("🚨 Emergency key rotation completed: reason={}", reason);

        Ok(())
    }

    /// Manually trigger key rotation
    pub async fn manual_rotation(&self, reason: &str) -> Result<()> {
        let old_key_id = {
            let current = self.current_key.read().await;
            current.key_id
        };

        self.perform_rotation(RotationEventType::Manual, old_key_id, reason)
            .await?;

        tracing::info!("🔄 Manual key rotation completed: reason={}", reason);

        Ok(())
    }

    /// Core rotation logic
    async fn perform_rotation(
        &self,
        event_type: RotationEventType,
        old_key_id: Uuid,
        reason: &str,
    ) -> Result<()> {
        // Generate new key
        let new_key = SecureKeyPair::generate_with_expiration(Some(
            self.config.rotation_interval + self.config.overlap_period,
        ))?;

        let new_managed_key = ManagedKey::new(
            new_key,
            self.config.rotation_interval,
            self.config.overlap_period,
        )?;

        let new_key_id = new_managed_key.key_id;

        // Atomic rotation: move current to previous, set new as current
        {
            let mut current = self.current_key.write().await;
            let mut previous = self.previous_keys.write().await;

            // Move current key to previous keys
            let old_key = std::mem::replace(&mut *current, new_managed_key);
            previous.push(old_key);

            // Keep only the most recent previous keys
            let previous_len = previous.len();
            if previous_len > self.config.max_previous_keys {
                previous.drain(0..previous_len - self.config.max_previous_keys);
            }

            // Remove any expired previous keys
            previous.retain(|key| !key.is_expired());
        }

        // Record rotation event
        let rotation_event = KeyRotationEvent {
            event_id: Uuid::new_v4(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event_type,
            old_key_id: Some(old_key_id),
            new_key_id,
            reason: reason.to_string(),
        };

        {
            let mut events = self.rotation_events.write().await;
            events.push(rotation_event);

            // Keep only recent events (last 100)
            let events_len = events.len();
            if events_len > 100 {
                events.drain(0..events_len - 100);
            }
        }

        // Update rotation count
        {
            let mut count = self.total_rotations.write().await;
            *count += 1;
        }

        tracing::info!(
            "🔄 Key rotation completed: old_key={}, new_key={}, reason={}",
            old_key_id,
            new_key_id,
            reason
        );

        Ok(())
    }

    /// Sign a message with the current key
    pub async fn sign(&self, message: &[u8]) -> Result<([u8; 64], u64)> {
        let current = self.current_key.read().await;
        current.key.sign_with_timestamp(message)
    }

    /// Verify a signature using current key or any valid previous key
    pub async fn verify(&self, message: &[u8], signature: &[u8; 64], timestamp: u64) -> Result<()> {
        // Try current key first
        let current = self.current_key.read().await;
        if current
            .key
            .verify_with_timestamp(message, signature, timestamp, 300)
            .is_ok()
        {
            return Ok(());
        }
        drop(current);

        // Try previous keys
        let previous = self.previous_keys.read().await;
        for prev_key in previous.iter().rev() {
            // Try most recent first
            if !prev_key.is_expired()
                && prev_key
                    .key
                    .verify_with_timestamp(message, signature, timestamp, 300)
                    .is_ok()
            {
                return Ok(());
            }
        }

        Err(crypto_error!(
            "Signature verification failed with all available keys"
        ))
    }

    /// Get current public key
    pub async fn public_key(&self) -> [u8; 32] {
        let current = self.current_key.read().await;
        current.key.public_key()
    }

    /// Get statistics about the rotation system
    pub async fn get_stats(&self) -> KeyRotationStats {
        let current = self.current_key.read().await;
        let previous = self.previous_keys.read().await;
        let events = self.rotation_events.read().await;
        let total_rotations = *self.total_rotations.read().await;
        let emergency_rotations = *self.emergency_rotations.read().await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let current_key_age = now.saturating_sub(current.created_at);
        let time_until_rotation = current.time_until_rotation();

        let last_rotation_timestamp = events
            .iter()
            .filter(|e| !matches!(e.event_type, RotationEventType::Startup))
            .next_back()
            .map(|e| e.timestamp);

        // Health checks and warnings
        let mut warnings = Vec::new();
        let mut is_healthy = true;

        if current.is_expired() {
            warnings.push("Current key has expired!".to_string());
            is_healthy = false;
        } else if time_until_rotation == 0 {
            warnings.push("Key rotation is overdue".to_string());
            is_healthy = false;
        } else if time_until_rotation < 3600 {
            // Less than 1 hour
            warnings.push("Key rotation due soon".to_string());
        }

        if previous.iter().any(|k| k.is_expired()) {
            warnings.push("Some previous keys have expired and should be cleaned up".to_string());
        }

        if emergency_rotations > 0 {
            warnings.push(format!(
                "System has {emergency_rotations} emergency rotations"
            ));
        }

        KeyRotationStats {
            current_key_id: current.key_id,
            current_key_age_seconds: current_key_age,
            time_until_rotation_seconds: time_until_rotation,
            previous_keys_count: previous.len(),
            total_rotations,
            last_rotation_timestamp,
            emergency_rotations,
            is_healthy,
            warnings,
        }
    }

    /// Get recent rotation events
    pub async fn get_recent_events(&self, limit: usize) -> Vec<KeyRotationEvent> {
        let events = self.rotation_events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Clean up expired previous keys
    pub async fn cleanup_expired_keys(&self) -> Result<usize> {
        let mut previous = self.previous_keys.write().await;
        let initial_count = previous.len();

        previous.retain(|key| !key.is_expired());

        let cleaned_count = initial_count - previous.len();

        if cleaned_count > 0 {
            tracing::info!("🧹 Cleaned up {} expired previous keys", cleaned_count);
        }

        Ok(cleaned_count)
    }
}

/// Background service for automatic key rotation
pub struct KeyRotationService {
    manager: Arc<KeyRotationManager>,
    stop_signal: tokio::sync::mpsc::Receiver<()>,
}

impl KeyRotationService {
    /// Create new rotation service
    pub fn new(
        manager: Arc<KeyRotationManager>,
        stop_signal: tokio::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self {
            manager,
            stop_signal,
        }
    }

    /// Start the background rotation service
    pub async fn run(mut self) {
        let check_interval = self.manager.config.check_interval;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(check_interval));

        tracing::info!(
            "🔄 Key rotation service started (check interval: {}s)",
            check_interval
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.check_and_rotate().await {
                        tracing::error!("❌ Key rotation check failed: {}", e);
                    }

                    if let Err(e) = self.manager.cleanup_expired_keys().await {
                        tracing::error!("❌ Key cleanup failed: {}", e);
                    }
                }
                _ = self.stop_signal.recv() => {
                    tracing::info!("🛑 Key rotation service stopping");
                    break;
                }
            }
        }

        tracing::info!("✅ Key rotation service stopped");
    }

    async fn check_and_rotate(&self) -> Result<()> {
        let rotated = self.manager.rotate_if_needed().await?;

        if rotated {
            tracing::info!("🔄 Automatic key rotation completed");
        }

        // Check system health
        let stats = self.manager.get_stats().await;
        if !stats.is_healthy {
            tracing::warn!(
                "⚠️  Key rotation system health issues: {:?}",
                stats.warnings
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_key_rotation_manager_creation() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        let stats = manager.get_stats().await;
        assert!(stats.is_healthy);
        assert_eq!(stats.previous_keys_count, 0);
        assert_eq!(stats.total_rotations, 0);
        assert!(stats.time_until_rotation_seconds > 0);
    }

    #[tokio::test]
    async fn test_signing_and_verification() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        let message = b"test message for signing";
        let (signature, timestamp) = manager.sign(message).await.unwrap();

        // Should verify with current key
        manager
            .verify(message, &signature, timestamp)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_manual_rotation() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        let stats_before = manager.get_stats().await;
        let original_key_id = stats_before.current_key_id;

        // Perform manual rotation
        manager.manual_rotation("Test rotation").await.unwrap();

        let stats_after = manager.get_stats().await;
        assert_ne!(stats_after.current_key_id, original_key_id);
        assert_eq!(stats_after.previous_keys_count, 1);
        assert_eq!(stats_after.total_rotations, 1);
    }

    #[tokio::test]
    async fn test_verification_with_previous_key() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        // Sign with current key
        let message = b"test message";
        let (signature, timestamp) = manager.sign(message).await.unwrap();

        // Rotate key
        manager.manual_rotation("Test").await.unwrap();

        // Should still verify with previous key
        manager
            .verify(message, &signature, timestamp)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_emergency_rotation() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        let stats_before = manager.get_stats().await;
        assert_eq!(stats_before.emergency_rotations, 0);

        manager
            .emergency_rotation("Key compromise detected")
            .await
            .unwrap();

        let stats_after = manager.get_stats().await;
        assert_eq!(stats_after.emergency_rotations, 1);
        assert_eq!(stats_after.total_rotations, 1);
    }

    #[tokio::test]
    async fn test_configuration_validation() {
        // Valid config
        let valid_config = KeyRotationConfig::default();
        assert!(valid_config.validate().is_ok());

        // Invalid config - overlap >= rotation
        let invalid_config = KeyRotationConfig {
            rotation_interval: 100,
            overlap_period: 100,
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());

        // Invalid config - no previous keys
        let invalid_config2 = KeyRotationConfig {
            max_previous_keys: 0,
            ..Default::default()
        };
        assert!(invalid_config2.validate().is_err());
    }

    #[tokio::test]
    async fn test_automatic_rotation_due_detection() {
        // Create manager with very short rotation interval
        let config = KeyRotationConfig {
            rotation_interval: 2, // 2 seconds
            overlap_period: 1,    // 1 second overlap (must be < rotation_interval)
            check_interval: 1,
            max_previous_keys: 2,
        };

        let manager = KeyRotationManager::new(config).await.unwrap();

        // Initially rotation should not be due
        let should_rotate_now = manager.rotate_if_needed().await.unwrap();
        assert!(!should_rotate_now);

        // Wait for rotation to become due
        sleep(Duration::from_millis(2100)).await;

        // Now rotation should be due
        let should_rotate_after = manager.rotate_if_needed().await.unwrap();
        assert!(should_rotate_after);

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_rotations, 1);
    }

    #[tokio::test]
    async fn test_max_previous_keys_limit() {
        let config = KeyRotationConfig {
            max_previous_keys: 2,
            ..KeyRotationConfig::for_testing()
        };

        let manager = KeyRotationManager::new(config).await.unwrap();

        // Perform multiple rotations
        for i in 1..=5 {
            manager
                .manual_rotation(&format!("Rotation {i}"))
                .await
                .unwrap();
        }

        let stats = manager.get_stats().await;
        // Should only keep max_previous_keys (2) previous keys
        assert!(stats.previous_keys_count <= 2);
        assert_eq!(stats.total_rotations, 5);
    }

    #[tokio::test]
    async fn test_rotation_events_tracking() {
        let manager = KeyRotationManager::for_testing().await.unwrap();

        // Perform different types of rotations
        manager.manual_rotation("Manual test").await.unwrap();
        manager.emergency_rotation("Emergency test").await.unwrap();

        let events = manager.get_recent_events(10).await;

        // Should have startup + manual + emergency = 3 events
        assert_eq!(events.len(), 3);

        // Check event types (most recent first)
        assert!(matches!(events[0].event_type, RotationEventType::Emergency));
        assert!(matches!(events[1].event_type, RotationEventType::Manual));
        assert!(matches!(events[2].event_type, RotationEventType::Startup));
    }
}
