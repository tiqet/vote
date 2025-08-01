//! Unified Security Context for Banking-Grade Security Management
//!
//! This module provides centralized security management that ties together all
//! security components: authentication, authorization, auditing, incident detection,
//! and security monitoring. It serves as the single source of truth for security
//! state and coordinates all security operations.
//!
//! Key features:
//! - Centralized security session management
//! - Comprehensive security audit logging
//! - Automatic security incident detection and response
//! - Security metrics and performance monitoring
//! - Integration with all crypto security components
//! - Banking-grade security event correlation

use crate::{crypto_error, voting_error, Result};
use crate::crypto::{
    SecureSaltManager, VotingTokenService, VotingLockService,
    key_rotation::KeyRotationManager, CryptoRateLimiter,
    voting_lock::{VotingMethod, LockResult},
    voting_token::{TokenResult, VotingToken},
    audit::{EnhancedAuditSystem, AuditConfig, ComplianceLevel, AuditQuery},
    security_monitoring::{SecurityPerformanceMonitor, SecurityOperation, SecurityTimingContext, SecurityTimer, SecurityMonitoringConfig},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use uuid::Uuid;

/// Maximum security events to keep in memory
const MAX_SECURITY_EVENTS: usize = 10000;

/// Maximum failed attempts before incident escalation
const MAX_FAILED_ATTEMPTS: usize = 5;

/// Time window for tracking failed attempts (seconds)
const FAILED_ATTEMPT_WINDOW: u64 = 300; // 5 minutes

/// Security event types for comprehensive auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    // Authentication Events
    LoginAttempt {
        voter_hash: String,
        election_id: Uuid,
        session_id: Option<String>,
        success: bool,
        timestamp: u64,
        ip_address: Option<String>,
    },
    TokenIssued {
        voter_hash: String,
        election_id: Uuid,
        token_id: String,
        session_id: Option<String>,
        timestamp: u64,
    },
    TokenValidated {
        voter_hash: String,
        election_id: Uuid,
        token_id: String,
        success: bool,
        timestamp: u64,
    },
    TokenInvalidated {
        voter_hash: String,
        election_id: Uuid,
        token_id: String,
        reason: String,
        timestamp: u64,
    },

    // Voting Events
    VotingLockAcquired {
        voter_hash: String,
        election_id: Uuid,
        method: VotingMethod,
        token_id: String,
        lock_id: Uuid,
        timestamp: u64,
    },
    VotingCompleted {
        voter_hash: String,
        election_id: Uuid,
        method: VotingMethod,
        vote_id: Option<Uuid>,
        completion_id: Uuid,
        timestamp: u64,
    },
    VotingBlocked {
        voter_hash: String,
        election_id: Uuid,
        reason: String,
        attempted_method: VotingMethod,
        timestamp: u64,
    },

    // Security Events
    RateLimitExceeded {
        voter_hash: String,
        operation: String,
        timestamp: u64,
    },
    KeyRotation {
        old_key_id: Option<Uuid>,
        new_key_id: Uuid,
        reason: String,
        timestamp: u64,
    },
    SecurityIncident {
        incident_id: Uuid,
        incident_type: SecurityIncidentType,
        voter_hash: String,
        description: String,
        severity: SecuritySeverity,
        timestamp: u64,
    },

    // System Events
    SessionLogout {
        voter_hash: String,
        election_id: Uuid,
        tokens_invalidated: u32,
        lock_released: bool,
        timestamp: u64,
    },
    CryptoOperation {
        operation: String,
        success: bool,
        duration_ms: u64,
        timestamp: u64,
    },
}

/// Types of security incidents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityIncidentType {
    RepeatedFailedAuthentication,
    TokenForgeryAttempt,
    DoubleVotingAttempt,
    SuspiciousTimingPattern,
    RateLimitAbuse,
    UnauthorizedKeyAccess,
    CryptoOperationFailure,
    AbnormalBehaviorPattern,
}

/// Security incident severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Active security session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySession {
    pub session_id: String,
    pub voter_hash: String,
    pub election_id: Uuid,
    pub created_at: u64,
    pub last_activity: u64,
    pub active_tokens: Vec<String>,
    pub voting_method: Option<VotingMethod>,
    pub security_level: SecurityLevel,
    pub failed_attempts: u32,
    pub ip_address: Option<String>,
}

/// Security levels for risk-based authentication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    Standard,
    Elevated,  // After failed attempts or suspicious activity
    High,      // Multiple security incidents
    Locked,    // Temporarily locked due to security concerns
}

/// Security metrics for monitoring and alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub successful_authentications: u64,
    pub failed_authentications: u64,
    pub tokens_issued: u64,
    pub tokens_invalidated: u64,
    pub votes_completed: u64,
    pub security_incidents: u64,
    pub rate_limit_violations: u64,
    pub key_rotations: u64,

    // Performance metrics
    pub avg_auth_time_ms: f64,
    pub avg_token_validation_time_ms: f64,
    pub avg_crypto_operation_time_ms: f64,

    // Security health indicators
    pub incident_rate_per_hour: f64,
    pub failed_auth_rate: f64,
    pub system_security_score: f64, // 0.0 to 1.0
}

/// Recent failed attempts tracking
#[derive(Debug, Clone)]
struct FailedAttempt {
    timestamp: u64,
    operation: String,
    reason: String,
}

/// Comprehensive security context that coordinates all security operations
pub struct SecurityContext {
    // Core components
    salt_manager: Arc<SecureSaltManager>,
    token_service: Arc<VotingTokenService>,
    lock_service: Arc<VotingLockService>,
    key_manager: Option<Arc<KeyRotationManager>>,
    rate_limiter: Arc<Mutex<CryptoRateLimiter>>,

    // Enhanced audit system
    audit_system: Arc<EnhancedAuditSystem>,

    // Security performance monitoring
    performance_monitor: Arc<SecurityPerformanceMonitor>,

    // Security state
    active_sessions: Arc<RwLock<HashMap<String, SecuritySession>>>,
    failed_attempts: Arc<RwLock<HashMap<String, VecDeque<FailedAttempt>>>>,
    security_metrics: Arc<RwLock<SecurityMetrics>>,

    // Configuration
    config: SecurityContextConfig,
}

/// Configuration for security context
#[derive(Debug, Clone)]
pub struct SecurityContextConfig {
    pub session_timeout_seconds: u64,
    pub max_failed_attempts: usize,
    pub failed_attempt_window_seconds: u64,
    pub incident_detection_enabled: bool,
    pub auto_response_enabled: bool,
    pub security_logging_enabled: bool,
}

impl Default for SecurityContextConfig {
    fn default() -> Self {
        Self {
            session_timeout_seconds: 1800, // 30 minutes
            max_failed_attempts: MAX_FAILED_ATTEMPTS,
            failed_attempt_window_seconds: FAILED_ATTEMPT_WINDOW,
            incident_detection_enabled: true,
            auto_response_enabled: true,
            security_logging_enabled: true,
        }
    }
}

impl SecurityContextConfig {
    pub fn for_testing() -> Self {
        Self {
            session_timeout_seconds: 300, // 5 minutes for testing
            max_failed_attempts: 3,
            failed_attempt_window_seconds: 60, // 1 minute for testing
            incident_detection_enabled: true,
            auto_response_enabled: true,
            security_logging_enabled: true,
        }
    }
}

impl SecurityContext {
    /// Create new security context with all components
    pub fn new(
        salt_manager: Arc<SecureSaltManager>,
        token_service: Arc<VotingTokenService>,
        lock_service: Arc<VotingLockService>,
        key_manager: Option<Arc<KeyRotationManager>>,
        rate_limiter: Arc<Mutex<CryptoRateLimiter>>,
        config: SecurityContextConfig,
    ) -> Self {
        let initial_metrics = SecurityMetrics {
            total_sessions: 0,
            active_sessions: 0,
            successful_authentications: 0,
            failed_authentications: 0,
            tokens_issued: 0,
            tokens_invalidated: 0,
            votes_completed: 0,
            security_incidents: 0,
            rate_limit_violations: 0,
            key_rotations: 0,
            avg_auth_time_ms: 0.0,
            avg_token_validation_time_ms: 0.0,
            avg_crypto_operation_time_ms: 0.0,
            incident_rate_per_hour: 0.0,
            failed_auth_rate: 0.0,
            system_security_score: 1.0,
        };

        // Initialize enhanced audit system
        let audit_config = AuditConfig {
            audit_source: "voting_security_context".to_string(),
            enable_streaming: config.security_logging_enabled,
            default_compliance_level: ComplianceLevel::High, // Default to high for voting systems
            ..AuditConfig::default()
        };
        let audit_system = Arc::new(EnhancedAuditSystem::new(audit_config));

        // Initialize security performance monitor
        let monitoring_config = SecurityMonitoringConfig {
            metrics_window_seconds: 300, // 5 minutes
            timing_anomaly_threshold_micros: 50,
            dos_detection_enabled: true,
            authentication_pattern_analysis: true,
            baseline_update_interval_seconds: 3600, // 1 hour
        };
        let performance_monitor = Arc::new(SecurityPerformanceMonitor::new(monitoring_config));

        Self {
            salt_manager,
            token_service,
            lock_service,
            key_manager,
            rate_limiter,
            audit_system,
            performance_monitor,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            security_metrics: Arc::new(RwLock::new(initial_metrics)),
            config,
        }
    }

    /// Create security context for testing
    pub fn for_testing(
        salt_manager: Arc<SecureSaltManager>,
        token_service: Arc<VotingTokenService>,
        lock_service: Arc<VotingLockService>,
    ) -> Self {
        let rate_limiter = Arc::new(Mutex::new(CryptoRateLimiter::new(100)));
        let config = SecurityContextConfig::for_testing();

        Self::new(
            salt_manager,
            token_service,
            lock_service,
            None,
            rate_limiter,
            config,
        )
    }

    /// Secure login with comprehensive security tracking
    pub async fn secure_login(
        &self,
        bank_id: &str,
        election_id: &Uuid,
        session_id: Option<String>,
        ip_address: Option<String>,
    ) -> Result<SecurityLoginResult> {
        let start_time = SystemTime::now();

        // Check rate limiting
        {
            let mut rate_limiter = self.rate_limiter.lock()
                .map_err(|_| crypto_error!("Rate limiter lock error"))?;

            if let Err(_) = rate_limiter.check_rate_limit() {
                self.log_security_event(SecurityEvent::RateLimitExceeded {
                    voter_hash: "rate_limited".to_string(),
                    operation: "login".to_string(),
                    timestamp: self.current_timestamp(),
                }).await;

                return Ok(SecurityLoginResult::RateLimited);
            }
        }

        // Generate voter hash
        let current_time = self.current_timestamp();
        let voter_hash = match self.salt_manager.hash_voter_identity_secure(
            bank_id, election_id, current_time, 300
        ) {
            Ok(hash) => hex::encode(hash),
            Err(e) => {
                self.log_failed_attempt(&format!("voter_hash_gen:{}", bank_id), "hash_generation_failed", &e.to_string()).await;
                return Err(e);
            }
        };

        // Start performance timing AFTER voter_hash is generated
        let context = SecurityTimingContext {
            voter_hash: Some(voter_hash.clone()),
            election_id: Some(*election_id),
            ..Default::default()
        };
        let timer = SecurityTimer::start(SecurityOperation::SecureLogin, context);

        // Check if voter is locked due to security incidents
        if let Some(session) = self.get_session(&voter_hash, election_id).await? {
            if session.security_level == SecurityLevel::Locked {
                self.log_security_event(SecurityEvent::LoginAttempt {
                    voter_hash: voter_hash.clone(),
                    election_id: *election_id,
                    session_id: session_id.clone(),
                    success: false,
                    timestamp: current_time,
                    ip_address: ip_address.clone(),
                }).await;

                let _ = timer.finish(false, &self.performance_monitor).await;
                return Ok(SecurityLoginResult::SecurityLocked {
                    reason: "Account temporarily locked due to security concerns".to_string()
                });
            }
        }

        // Issue voting token
        let token_result = match self.token_service.issue_token(
            &self.salt_manager,
            &voter_hash,
            election_id,
            session_id.clone(),
        ) {
            Ok(result) => result,
            Err(e) => {
                self.log_failed_attempt(&voter_hash, "token_issuance", &e.to_string()).await;

                self.log_security_event(SecurityEvent::LoginAttempt {
                    voter_hash: voter_hash.clone(),
                    election_id: *election_id,
                    session_id,
                    success: false,
                    timestamp: current_time,
                    ip_address,
                }).await;

                let _ = timer.finish(false, &self.performance_monitor).await;
                return Err(e);
            }
        };

        let voting_token = match token_result {
            TokenResult::Issued(token) => token,
            TokenResult::TooManyTokens { active_count } => {
                self.log_security_event(SecurityEvent::LoginAttempt {
                    voter_hash: voter_hash.clone(),
                    election_id: *election_id,
                    session_id,
                    success: false,
                    timestamp: current_time,
                    ip_address,
                }).await;

                let _ = timer.finish(false, &self.performance_monitor).await;
                return Ok(SecurityLoginResult::TooManyTokens { active_count });
            }
            _ => {
                let _ = timer.finish(false, &self.performance_monitor).await;
                return Err(voting_error!("Unexpected token result during login"));
            }
        };

        // Create or update security session
        let session_id = session_id.unwrap_or_else(|| format!("session_{}", Uuid::new_v4()));
        let security_session = SecuritySession {
            session_id: session_id.clone(),
            voter_hash: voter_hash.clone(),
            election_id: *election_id,
            created_at: current_time,
            last_activity: current_time,
            active_tokens: vec![voting_token.token_id.clone()],
            voting_method: None,
            security_level: SecurityLevel::Standard,
            failed_attempts: 0,
            ip_address: ip_address.clone(),
        };

        // Store session
        {
            let mut sessions = self.active_sessions.write()
                .map_err(|_| crypto_error!("Session storage write error"))?;

            let session_key = format!("{}:{}", voter_hash, election_id);
            sessions.insert(session_key, security_session);
        }

        // Log successful events
        self.log_security_event(SecurityEvent::LoginAttempt {
            voter_hash: voter_hash.clone(),
            election_id: *election_id,
            session_id: Some(session_id.clone()),
            success: true,
            timestamp: current_time,
            ip_address,
        }).await;

        self.log_security_event(SecurityEvent::TokenIssued {
            voter_hash: voter_hash.clone(),
            election_id: *election_id,
            token_id: voting_token.token_id.clone(),
            session_id: Some(session_id.clone()),
            timestamp: current_time,
        }).await;

        // Update metrics and complete performance timing
        self.update_auth_metrics(start_time, true).await;
        let _ = timer.finish(true, &self.performance_monitor).await;

        tracing::info!(
            "🔐 Secure login successful: voter={}, session={}, token={}",
            &voter_hash[..8],
            &session_id[..8],
            &voting_token.token_id[..12]
        );

        Ok(SecurityLoginResult::Success {
            token: voting_token,
            session_id,
            security_level: SecurityLevel::Standard,
        })
    }

    /// Secure voting with comprehensive security checks
    pub async fn secure_vote(
        &self,
        token_id: &str,
        voter_hash: &str,
        election_id: &Uuid,
        voting_method: VotingMethod,
    ) -> Result<SecurityVoteResult> {
        let current_time = self.current_timestamp();

        // Update session activity
        self.update_session_activity(voter_hash, election_id).await?;

        // Validate token with security logging
        let token_validation = self.token_service.validate_token(
            &self.salt_manager,
            token_id,
            voter_hash,
            election_id,
        )?;

        let _valid_token = match token_validation {
            TokenResult::Valid(token) => {
                self.log_security_event(SecurityEvent::TokenValidated {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    token_id: token_id.to_string(),
                    success: true,
                    timestamp: current_time,
                }).await;
                token
            }
            TokenResult::Invalid { reason } => {
                self.log_security_event(SecurityEvent::TokenValidated {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    token_id: token_id.to_string(),
                    success: false,
                    timestamp: current_time,
                }).await;

                return Ok(SecurityVoteResult::InvalidToken { reason });
            }
            _ => {
                return Ok(SecurityVoteResult::InvalidToken {
                    reason: "Unexpected token validation result".to_string()
                });
            }
        };

        // Attempt to acquire voting lock
        let lock_result = self.lock_service.acquire_lock_with_token(
            &self.salt_manager,
            token_id,
            voter_hash,
            election_id,
            voting_method.clone(),
        )?;

        match lock_result {
            LockResult::Acquired(lock) => {
                // Update session with voting method
                self.update_session_voting_method(voter_hash, election_id, Some(voting_method.clone())).await?;

                self.log_security_event(SecurityEvent::VotingLockAcquired {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    method: voting_method,
                    token_id: token_id.to_string(),
                    lock_id: lock.lock_id,
                    timestamp: current_time,
                }).await;

                Ok(SecurityVoteResult::LockAcquired { lock })
            }
            LockResult::AlreadyVoted { completion, original_method } => {
                let reason = format!("Already voted via {:?}", original_method);

                self.log_security_event(SecurityEvent::VotingBlocked {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    reason: reason.clone(),
                    attempted_method: voting_method.clone(),
                    timestamp: current_time,
                }).await;

                // Detect potential double voting attempt (security incident)
                self.detect_double_voting_incident(voter_hash, election_id, &original_method, &voting_method).await;

                Ok(SecurityVoteResult::AlreadyVoted { completion, original_method })
            }
            LockResult::AlreadyLocked { existing_lock, conflict_method } => {
                let reason = format!("Concurrent voting session active via {:?}", conflict_method);

                self.log_security_event(SecurityEvent::VotingBlocked {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    reason: reason.clone(),
                    attempted_method: voting_method.clone(),
                    timestamp: current_time,
                }).await;

                Ok(SecurityVoteResult::ConcurrentVoting { existing_lock, conflict_method })
            }
            LockResult::InvalidToken { reason } => {
                self.log_failed_attempt(voter_hash, "voting_lock_acquisition", &reason).await;
                Ok(SecurityVoteResult::InvalidToken { reason })
            }
            LockResult::ExpiredLockRemoved(lock) => {
                self.log_security_event(SecurityEvent::VotingLockAcquired {
                    voter_hash: voter_hash.to_string(),
                    election_id: *election_id,
                    method: voting_method.clone(),
                    token_id: token_id.to_string(),
                    lock_id: lock.lock_id,
                    timestamp: current_time,
                }).await;

                Ok(SecurityVoteResult::LockAcquired { lock })
            }
        }
    }

    /// Complete voting with security tracking
    pub async fn complete_voting(
        &self,
        lock: &crate::crypto::voting_lock::VoterLock,
        vote_id: Option<Uuid>,
    ) -> Result<crate::crypto::VotingCompletion> {
        let current_time = self.current_timestamp();

        // Complete voting through lock service (this invalidates the token)
        let completion = self.lock_service.complete_voting_with_token_cleanup(lock, vote_id)?;

        // Log completion event
        self.log_security_event(SecurityEvent::VotingCompleted {
            voter_hash: lock.voter_hash.clone(),
            election_id: lock.election_id,
            method: lock.method.clone(),
            vote_id,
            completion_id: completion.completion_id,
            timestamp: current_time,
        }).await;

        // Log token invalidation (since complete_voting_with_token_cleanup invalidates the token)
        self.log_security_event(SecurityEvent::TokenInvalidated {
            voter_hash: lock.voter_hash.clone(),
            election_id: lock.election_id,
            token_id: lock.token_id.clone(),
            reason: "Token invalidated after vote completion".to_string(),
            timestamp: current_time,
        }).await;

        // Update session
        self.update_session_voting_method(&lock.voter_hash, &lock.election_id, None).await?;

        // Update metrics
        {
            let mut metrics = self.security_metrics.write()
                .map_err(|_| crypto_error!("Metrics write error"))?;
            metrics.votes_completed += 1;
            metrics.tokens_invalidated += 1; // Track token invalidation from voting completion
        }

        tracing::info!(
            "🗳️ Secure voting completed: voter={}, completion={}, token_invalidated={}",
            &lock.voter_hash[..8],
            completion.completion_id,
            &lock.token_id[..12]
        );

        Ok(completion)
    }

    /// Secure logout with comprehensive cleanup
    pub async fn secure_logout(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
    ) -> Result<crate::crypto::LogoutResult> {
        let current_time = self.current_timestamp();

        // Perform logout through lock service
        let logout_result = self.lock_service.logout_voter(voter_hash, election_id)?;

        // Remove session
        {
            let mut sessions = self.active_sessions.write()
                .map_err(|_| crypto_error!("Session storage write error"))?;

            let session_key = format!("{}:{}", voter_hash, election_id);
            sessions.remove(&session_key);
        }

        // Log logout event
        self.log_security_event(SecurityEvent::SessionLogout {
            voter_hash: voter_hash.to_string(),
            election_id: *election_id,
            tokens_invalidated: logout_result.invalidated_tokens,
            lock_released: logout_result.released_lock,
            timestamp: current_time,
        }).await;

        // Update metrics
        {
            let mut metrics = self.security_metrics.write()
                .map_err(|_| crypto_error!("Metrics write error"))?;
            metrics.tokens_invalidated += logout_result.invalidated_tokens as u64;
        }

        tracing::info!(
            "👋 Secure logout: voter={}, tokens_invalidated={}, lock_released={}",
            &voter_hash[..8],
            logout_result.invalidated_tokens,
            logout_result.released_lock
        );

        Ok(logout_result)
    }

    /// Get comprehensive security status
    pub async fn get_security_status(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
    ) -> Result<SecurityStatus> {
        let voting_status = self.lock_service.get_voting_status(voter_hash, election_id)?;
        let session = self.get_session(voter_hash, election_id).await?;
        let failed_attempts = self.get_failed_attempts_count(voter_hash).await;
        let recent_events = self.get_recent_security_events(voter_hash, 10).await;

        Ok(SecurityStatus {
            voting_status,
            session,
            failed_attempts,
            recent_events,
            system_security_level: self.calculate_system_security_level().await,
        })
    }

    /// Get comprehensive security metrics
    pub async fn get_security_metrics(&self) -> Result<SecurityMetrics> {
        let metrics = self.security_metrics.read()
            .map_err(|_| crypto_error!("Metrics read error"))?;

        let mut updated_metrics = metrics.clone();

        // Calculate real-time metrics
        let active_sessions = {
            let sessions = self.active_sessions.read()
                .map_err(|_| crypto_error!("Session read error"))?;
            sessions.len() as u64
        };

        updated_metrics.active_sessions = active_sessions;
        updated_metrics.system_security_score = self.calculate_system_security_score(&updated_metrics);

        Ok(updated_metrics)
    }

    /// Private helper methods

    async fn log_security_event(&self, event: SecurityEvent) {
        if !self.config.security_logging_enabled {
            return;
        }

        // Determine compliance level based on event type
        let compliance_level = match &event {
            SecurityEvent::SecurityIncident { severity, .. } => match severity {
                SecuritySeverity::Critical => ComplianceLevel::Critical,
                SecuritySeverity::High => ComplianceLevel::High,
                _ => ComplianceLevel::Standard,
            },
            SecurityEvent::VotingCompleted { .. } => ComplianceLevel::Critical,
            SecurityEvent::KeyRotation { .. } => ComplianceLevel::High,
            SecurityEvent::LoginAttempt { success: false, .. } => ComplianceLevel::High,
            SecurityEvent::VotingBlocked { .. } => ComplianceLevel::High,
            _ => ComplianceLevel::Standard,
        };

        // Generate correlation ID for related events
        let correlation_id = self.generate_correlation_id(&event);

        // Log to enhanced audit system
        if let Err(e) = self.audit_system.log_security_event(
            event.clone(),
            Some(compliance_level),
            correlation_id,
        ).await {
            tracing::error!("Failed to log security event to audit system: {}", e);
        }

        // Log to tracing system for immediate visibility
        match event {
            SecurityEvent::SecurityIncident { incident_type, severity, .. } => {
                tracing::warn!("🚨 Security incident: {:?} (severity: {:?})", incident_type, severity);
            }
            SecurityEvent::LoginAttempt { success: false, .. } => {
                tracing::warn!("🔐 Failed login attempt");
            }
            SecurityEvent::VotingBlocked { reason, .. } => {
                tracing::warn!("🚫 Voting blocked: {}", reason);
            }
            _ => {
                tracing::debug!("🔒 Security event: {:?}", event);
            }
        }
    }

    async fn log_failed_attempt(&self, identifier: &str, operation: &str, reason: &str) {
        let current_time = self.current_timestamp();

        let failed_attempt = FailedAttempt {
            timestamp: current_time,
            operation: operation.to_string(),
            reason: reason.to_string(),
        };

        {
            let mut failed_attempts = self.failed_attempts.write().unwrap();
            let attempts = failed_attempts.entry(identifier.to_string()).or_insert_with(VecDeque::new);

            attempts.push_back(failed_attempt);

            // Clean old attempts
            let cutoff_time = current_time - self.config.failed_attempt_window_seconds;
            while let Some(front) = attempts.front() {
                if front.timestamp < cutoff_time {
                    attempts.pop_front();
                } else {
                    break;
                }
            }

            // Check for incident
            if attempts.len() >= self.config.max_failed_attempts {
                if self.config.incident_detection_enabled {
                    let incident_id = Uuid::new_v4();
                    let incident_event = SecurityEvent::SecurityIncident {
                        incident_id,
                        incident_type: SecurityIncidentType::RepeatedFailedAuthentication,
                        voter_hash: identifier.to_string(),
                        description: format!("Too many failed {} attempts", operation),
                        severity: SecuritySeverity::High,
                        timestamp: current_time,
                    };

                    self.log_security_event(incident_event).await;

                    if self.config.auto_response_enabled {
                        self.escalate_security_level(identifier).await;
                    }
                }
            }
        }

        // Update metrics
        {
            let mut metrics = self.security_metrics.write().unwrap();
            metrics.failed_authentications += 1;
        }
    }

    async fn detect_double_voting_incident(
        &self,
        voter_hash: &str,
        _election_id: &Uuid,
        original_method: &VotingMethod,
        attempted_method: &VotingMethod,
    ) {
        if original_method != attempted_method {
            let incident_event = SecurityEvent::SecurityIncident {
                incident_id: Uuid::new_v4(),
                incident_type: SecurityIncidentType::DoubleVotingAttempt,
                voter_hash: voter_hash.to_string(),
                description: format!("Attempted {:?} voting after {:?} completion", attempted_method, original_method),
                severity: SecuritySeverity::Critical,
                timestamp: self.current_timestamp(),
            };

            self.log_security_event(incident_event).await;
            self.escalate_security_level(voter_hash).await;
        }
    }

    async fn escalate_security_level(&self, voter_identifier: &str) {
        if let Ok(mut sessions) = self.active_sessions.write() {
            for (key, session) in sessions.iter_mut() {
                if key.starts_with(voter_identifier) {
                    session.security_level = match session.security_level {
                        SecurityLevel::Standard => SecurityLevel::Elevated,
                        SecurityLevel::Elevated => SecurityLevel::High,
                        SecurityLevel::High => SecurityLevel::Locked,
                        SecurityLevel::Locked => SecurityLevel::Locked,
                    };
                    session.last_activity = self.current_timestamp();
                }
            }
        }
    }

    async fn get_session(&self, voter_hash: &str, election_id: &Uuid) -> Result<Option<SecuritySession>> {
        let sessions = self.active_sessions.read()
            .map_err(|_| crypto_error!("Session read error"))?;

        let session_key = format!("{}:{}", voter_hash, election_id);
        Ok(sessions.get(&session_key).cloned())
    }

    async fn update_session_activity(&self, voter_hash: &str, election_id: &Uuid) -> Result<()> {
        let mut sessions = self.active_sessions.write()
            .map_err(|_| crypto_error!("Session write error"))?;

        let session_key = format!("{}:{}", voter_hash, election_id);
        if let Some(session) = sessions.get_mut(&session_key) {
            session.last_activity = self.current_timestamp();
        }

        Ok(())
    }

    async fn update_session_voting_method(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
        voting_method: Option<VotingMethod>,
    ) -> Result<()> {
        let mut sessions = self.active_sessions.write()
            .map_err(|_| crypto_error!("Session write error"))?;

        let session_key = format!("{}:{}", voter_hash, election_id);
        if let Some(session) = sessions.get_mut(&session_key) {
            session.voting_method = voting_method;
            session.last_activity = self.current_timestamp();
        }

        Ok(())
    }

    async fn get_failed_attempts_count(&self, voter_hash: &str) -> u32 {
        let failed_attempts = self.failed_attempts.read().unwrap();
        failed_attempts.get(voter_hash)
            .map(|attempts| attempts.len() as u32)
            .unwrap_or(0)
    }

    async fn get_recent_security_events(&self, voter_hash: &str, limit: usize) -> Vec<SecurityEvent> {
        // Query audit system for recent events related to this voter
        let query = AuditQuery {
            limit: Some(limit),
            ..Default::default()
        };

        match self.audit_system.query_audit_records(query).await {
            Ok(audit_records) => {
                audit_records
                    .into_iter()
                    .filter(|record| self.audit_record_involves_voter(record, voter_hash))
                    .map(|record| record.security_event)
                    .collect()
            }
            Err(e) => {
                tracing::error!("Failed to query audit records: {}", e);
                Vec::new()
            }
        }
    }

    fn audit_record_involves_voter(&self, record: &crate::crypto::audit::AuditRecord, voter_hash: &str) -> bool {
        self.event_involves_voter(&record.security_event, voter_hash)
    }

    fn event_involves_voter(&self, event: &SecurityEvent, voter_hash: &str) -> bool {
        match event {
            SecurityEvent::LoginAttempt { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::TokenIssued { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::TokenValidated { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::TokenInvalidated { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::VotingLockAcquired { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::VotingCompleted { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::VotingBlocked { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::RateLimitExceeded { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::SecurityIncident { voter_hash: vh, .. } => vh == voter_hash,
            SecurityEvent::SessionLogout { voter_hash: vh, .. } => vh == voter_hash,
            _ => false,
        }
    }

    async fn calculate_system_security_level(&self) -> SecurityLevel {
        let metrics = self.security_metrics.read().unwrap();

        if metrics.incident_rate_per_hour > 10.0 || metrics.failed_auth_rate > 0.5 {
            SecurityLevel::High
        } else if metrics.incident_rate_per_hour > 5.0 || metrics.failed_auth_rate > 0.2 {
            SecurityLevel::Elevated
        } else {
            SecurityLevel::Standard
        }
    }

    fn calculate_system_security_score(&self, metrics: &SecurityMetrics) -> f64 {
        let mut score = 1.0;

        // Reduce score based on incidents
        if metrics.security_incidents > 0 {
            score -= (metrics.incident_rate_per_hour * 0.1).min(0.5);
        }

        // Reduce score based on failed authentications
        if metrics.failed_authentications > 0 {
            score -= (metrics.failed_auth_rate * 0.2).min(0.3);
        }

        // Reduce score based on rate limit violations
        if metrics.rate_limit_violations > 0 {
            score -= (metrics.rate_limit_violations as f64 / 1000.0).min(0.2);
        }

        score.max(0.0)
    }

    fn generate_correlation_id(&self, event: &SecurityEvent) -> Option<String> {
        match event {
            SecurityEvent::LoginAttempt { voter_hash, election_id, .. } => {
                Some(format!("login_{}_{}", &voter_hash[..8], election_id))
            }
            SecurityEvent::VotingLockAcquired { voter_hash, election_id, .. } => {
                Some(format!("voting_{}_{}", &voter_hash[..8], election_id))
            }
            SecurityEvent::VotingCompleted { voter_hash, election_id, .. } => {
                Some(format!("completion_{}_{}", &voter_hash[..8], election_id))
            }
            SecurityEvent::SecurityIncident { incident_id, .. } => {
                Some(format!("incident_{}", incident_id))
            }
            _ => None,
        }
    }

    async fn update_auth_metrics(&self, start_time: SystemTime, success: bool) {
        let duration = start_time.elapsed().unwrap_or_default();

        let mut metrics = self.security_metrics.write().unwrap();

        if success {
            metrics.successful_authentications += 1;
        } else {
            metrics.failed_authentications += 1;
        }

        // Update average authentication time
        let new_time_ms = duration.as_millis() as f64;
        if metrics.total_sessions == 0 {
            metrics.avg_auth_time_ms = new_time_ms;
        } else {
            metrics.avg_auth_time_ms = (metrics.avg_auth_time_ms * metrics.total_sessions as f64 + new_time_ms) / (metrics.total_sessions + 1) as f64;
        }

        metrics.total_sessions += 1;

        // Calculate rates
        if metrics.successful_authentications + metrics.failed_authentications > 0 {
            metrics.failed_auth_rate = metrics.failed_authentications as f64 / (metrics.successful_authentications + metrics.failed_authentications) as f64;
        }
    }

    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get access to the enhanced audit system
    pub fn audit_system(&self) -> &Arc<EnhancedAuditSystem> {
        &self.audit_system
    }

    /// Query audit records with criteria
    pub async fn query_audit_records(&self, query: AuditQuery) -> Result<Vec<crate::crypto::audit::AuditRecord>> {
        self.audit_system.query_audit_records(query).await
    }

    /// Export compliance report
    pub async fn export_compliance_report(&self, query: AuditQuery) -> Result<crate::crypto::audit::ComplianceReport> {
        self.audit_system.export_compliance_report(query).await
    }

    /// Verify audit trail integrity
    pub async fn verify_audit_integrity(&self) -> Result<crate::crypto::audit::AuditIntegrityReport> {
        self.audit_system.verify_integrity().await
    }

    /// Get audit trail statistics
    pub async fn get_audit_statistics(&self) -> Result<crate::crypto::audit::AuditTrailStatistics> {
        self.audit_system.get_statistics().await
    }

    /// Clean up expired audit records
    pub async fn cleanup_expired_audit_records(&self) -> Result<crate::crypto::audit::AuditCleanupReport> {
        self.audit_system.cleanup_expired().await
    }

    /// Get access to the security performance monitor
    pub fn performance_monitor(&self) -> &Arc<SecurityPerformanceMonitor> {
        &self.performance_monitor
    }

    /// Get current security performance metrics
    pub async fn get_security_performance_metrics(&self) -> Result<crate::crypto::security_monitoring::SecurityPerformanceMetrics> {
        self.performance_monitor.get_current_metrics().await
    }

    /// Get timing statistics for a specific security operation
    pub async fn get_operation_timing_stats(&self, operation: &SecurityOperation) -> Result<Option<crate::crypto::security_monitoring::OperationTimingStats>> {
        self.performance_monitor.get_timing_stats(operation).await
    }

    /// Get authentication patterns analysis
    pub async fn get_authentication_patterns(&self) -> Result<Vec<crate::crypto::security_monitoring::AuthenticationPattern>> {
        self.performance_monitor.get_auth_patterns().await
    }

    /// Get detected DoS patterns
    pub async fn get_dos_patterns(&self) -> Result<Vec<crate::crypto::security_monitoring::DoSPattern>> {
        self.performance_monitor.get_dos_patterns().await
    }

    /// Update security performance baselines
    pub async fn update_security_baselines(&self) -> Result<()> {
        self.performance_monitor.update_baselines().await
    }

    /// Record custom security timing (for external integrations)
    pub async fn record_security_timing(
        &self,
        operation: SecurityOperation,
        duration: std::time::Duration,
        success: bool,
        context: SecurityTimingContext,
    ) -> Result<crate::crypto::security_monitoring::SecurityThreatAssessment> {
        self.performance_monitor.record_timing(operation, duration, success, context).await
    }

    /// Record resource usage for DoS detection
    pub async fn record_resource_usage(&self, usage: crate::crypto::security_monitoring::ResourceUsage) -> Result<()> {
        self.performance_monitor.record_resource_usage(usage).await
    }
}

/// Result of secure login operation
#[derive(Debug)]
pub enum SecurityLoginResult {
    Success {
        token: VotingToken,
        session_id: String,
        security_level: SecurityLevel,
    },
    RateLimited,
    TooManyTokens {
        active_count: usize,
    },
    SecurityLocked {
        reason: String,
    },
}

/// Result of secure voting operation
#[derive(Debug)]
pub enum SecurityVoteResult {
    LockAcquired {
        lock: crate::crypto::voting_lock::VoterLock,
    },
    AlreadyVoted {
        completion: crate::crypto::VotingCompletion,
        original_method: VotingMethod,
    },
    ConcurrentVoting {
        existing_lock: crate::crypto::voting_lock::VoterLock,
        conflict_method: VotingMethod,
    },
    InvalidToken {
        reason: String,
    },
}

/// Comprehensive security status
#[derive(Debug)]
pub struct SecurityStatus {
    pub voting_status: crate::crypto::VotingStatus,
    pub session: Option<SecuritySession>,
    pub failed_attempts: u32,
    pub recent_events: Vec<SecurityEvent>,
    pub system_security_level: SecurityLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SecureSaltManager, SecurityOperation, SecurityTimingContext};
    use std::time::Duration;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_unified_security_context_creation() {
        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let security_context = SecurityContext::for_testing(
            salt_manager,
            token_service,
            Arc::new(lock_service),
        );

        let metrics = security_context.get_security_metrics().await.unwrap();
        assert_eq!(metrics.total_sessions, 0);
        assert_eq!(metrics.system_security_score, 1.0);

        println!("✅ Security context created successfully");
    }

    #[tokio::test]
    async fn test_secure_login_workflow() {
        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let security_context = SecurityContext::for_testing(
            salt_manager,
            token_service,
            Arc::new(lock_service),
        );

        let bank_id = "CZ1234567890";
        let election_id = Uuid::new_v4();
        let session_id = Some("test_session_123".to_string());

        let login_result = security_context.secure_login(
            bank_id,
            &election_id,
            session_id.clone(),
            Some("192.168.1.100".to_string()),
        ).await.unwrap();

        match login_result {
            SecurityLoginResult::Success { token, session_id: returned_session, security_level } => {
                assert_eq!(security_level, SecurityLevel::Standard);
                assert_eq!(returned_session, session_id.unwrap());
                println!("✅ Secure login successful: token={}", &token.token_id[..12]);
            }
            _ => panic!("Expected successful login"),
        }

        let metrics = security_context.get_security_metrics().await.unwrap();
        assert_eq!(metrics.successful_authentications, 1);
        assert_eq!(metrics.total_sessions, 1);

        println!("✅ Secure login workflow completed");
    }

    #[tokio::test]
    async fn test_security_incident_detection() {
        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let security_context = SecurityContext::for_testing(
            salt_manager,
            token_service,
            Arc::new(lock_service),
        );

        let voter_hash = hex::encode([1u8; 32]);

        // Simulate multiple failed attempts
        for i in 0..5 {
            security_context.log_failed_attempt(
                &voter_hash,
                "test_operation",
                &format!("Failed attempt {}", i + 1),
            ).await;
        }

        let failed_count = security_context.get_failed_attempts_count(&voter_hash).await;
        assert!(failed_count >= 3); // Should have triggered incident detection

        println!("✅ Security incident detection working: {} failed attempts", failed_count);
    }

    #[tokio::test]
    async fn test_complete_voting_workflow_with_security() {
        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let security_context = SecurityContext::for_testing(
            salt_manager,
            token_service,
            Arc::new(lock_service),
        );

        let bank_id = "CZ1234567890";
        let election_id = Uuid::new_v4();

        // 1. Secure login
        let login_result = security_context.secure_login(
            bank_id,
            &election_id,
            Some("complete_workflow_session".to_string()),
            None,
        ).await.unwrap();

        let (token, session_id) = match login_result {
            SecurityLoginResult::Success { token, session_id, .. } => (token, session_id),
            _ => panic!("Expected successful login"),
        };

        let voter_hash = token.voter_hash.clone();

        // 2. Secure voting
        let vote_result = security_context.secure_vote(
            &token.token_id,
            &voter_hash,
            &election_id,
            VotingMethod::Digital,
        ).await.unwrap();

        let voting_lock = match vote_result {
            SecurityVoteResult::LockAcquired { lock } => lock,
            _ => panic!("Expected to acquire voting lock"),
        };

        // 3. Complete voting
        let vote_id = Uuid::new_v4();
        let completion = security_context.complete_voting(&voting_lock, Some(vote_id)).await.unwrap();

        // 4. Secure logout
        let logout_result = security_context.secure_logout(&voter_hash, &election_id).await.unwrap();

        // 5. Verify final state
        let final_metrics = security_context.get_security_metrics().await.unwrap();
        assert_eq!(final_metrics.votes_completed, 1);
        assert!(final_metrics.tokens_invalidated > 0);

        println!("✅ Complete secure voting workflow successful");
        println!("   Completion: {}", completion.completion_id);
        println!("   Tokens invalidated: {}", logout_result.invalidated_tokens);
        println!("   Security score: {:.2}", final_metrics.system_security_score);

        // Verify audit trail
        let audit_integrity = security_context.verify_audit_integrity().await.unwrap();
        assert!(audit_integrity.hash_chain_valid);
        println!("   Audit integrity: ✅ Verified");

        let audit_stats = security_context.get_audit_statistics().await.unwrap();
        println!("   Audit records: {}", audit_stats.total_records);
        assert!(audit_stats.total_records > 0);

        // Verify performance monitoring
        let performance_metrics = security_context.get_security_performance_metrics().await.unwrap();
        println!("   Security health score: {:.2}", performance_metrics.security_health_score);
        assert!(performance_metrics.authentication_attempts > 0);

        // Check timing stats for login operation
        let login_stats = security_context.get_operation_timing_stats(&SecurityOperation::SecureLogin).await.unwrap();
        if let Some(stats) = login_stats {
            println!("   Login timing - avg: {:.2}μs, samples: {}", stats.avg_micros, stats.sample_count);
            assert!(stats.sample_count > 0);
        }
    }
}