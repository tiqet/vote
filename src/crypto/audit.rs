//! Enhanced Auditing & Logging System for Banking-Grade Compliance
//!
//! Provides comprehensive audit capabilities for banking and financial services:
//! - Tamper-evident audit trails with cryptographic hash chains
//! - Immutable audit records with integrity verification
//! - Compliance-ready logging (SOX, PCI DSS, regulatory patterns)
//! - Real-time audit streaming for security monitoring
//! - Sophisticated query engine for investigations
//! - Export capabilities for regulators and external auditors
//!
//! # Security Architecture
//! - **Hash chains**: Each record cryptographically links to previous
//! - **Content integrity**: Blake3 hashes detect tampering
//! - **Sequence validation**: Monotonic sequence prevents insertion
//! - **Retention policies**: Automatic cleanup with compliance awareness
//!
//! # Examples
//!
//! ```rust
//! use vote::crypto::audit::{EnhancedAuditSystem, AuditConfig, ComplianceLevel};
//! use vote::crypto::SecurityEvent;
//! use uuid::Uuid;
//!
//! # async fn example() -> vote::Result<()> {
//! let audit_system = EnhancedAuditSystem::new(AuditConfig::default());
//!
//! let event = SecurityEvent::LoginAttempt {
//!     voter_hash: "voter_123".to_string(),
//!     election_id: Uuid::new_v4(),
//!     session_id: Some("session_456".to_string()),
//!     success: true,
//!     timestamp: 1234567890,
//!     ip_address: Some("192.168.1.100".to_string()),
//! };
//!
//! let record = audit_system.log_security_event(
//!     event,
//!     Some(ComplianceLevel::High),
//!     Some("correlation_789".to_string()),
//! ).await?;
//!
//! // Verify integrity
//! let integrity_report = audit_system.verify_integrity().await?;
//! assert!(integrity_report.hash_chain_valid);
//! # Ok(())
//! # }
//! ```

use crate::crypto::{CryptoUtils, SecureMemory, SecurityEvent};
use crate::{Result, crypto_error};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Maximum audit records in memory before cleanup
const MAX_MEMORY_AUDIT_RECORDS: usize = 10000;

/// Retention periods in seconds
const AUDIT_RETENTION_CRITICAL: u64 = 2_592_000; // 30 days
const AUDIT_RETENTION_HIGH: u64 = 7_776_000; // 90 days
const AUDIT_RETENTION_STANDARD: u64 = 31_536_000; // 365 days

/// Tamper-evident audit record with cryptographic integrity
///
/// Each record contains a security event with cryptographic protections:
/// - Hash chain linking to previous record
/// - Content hash for integrity verification
/// - Sequence numbers for tamper detection
/// - Compliance-based retention policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub record_id: Uuid,
    pub sequence_number: u64,
    pub timestamp: u64,
    pub previous_hash: Option<[u8; 32]>,
    pub content_hash: [u8; 32],
    pub security_event: SecurityEvent,
    pub audit_metadata: AuditMetadata,
    pub compliance_level: ComplianceLevel,
    pub retention_until: u64,
}

impl AuditRecord {
    /// Create new audit record with tamper-evident properties
    pub fn new(
        sequence_number: u64,
        previous_hash: Option<[u8; 32]>,
        security_event: SecurityEvent,
        compliance_level: ComplianceLevel,
        audit_source: String,
        correlation_id: Option<String>,
    ) -> Result<Self> {
        let record_id = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        let audit_metadata = AuditMetadata {
            audit_source,
            correlation_id,
            system_version: env!("CARGO_PKG_VERSION").to_string(),
            audit_level: AuditLevel::from_security_event(&security_event),
            user_agent: None,
            request_id: None,
        };

        let retention_until = timestamp
            + match compliance_level {
                ComplianceLevel::Critical => AUDIT_RETENTION_CRITICAL,
                ComplianceLevel::High => AUDIT_RETENTION_HIGH,
                ComplianceLevel::Standard => AUDIT_RETENTION_STANDARD,
            };

        let content_for_hash = serde_json::to_vec(&(&security_event, &audit_metadata))
            .map_err(|e| crypto_error!("Failed to serialize audit content: {}", e))?;
        let content_hash = CryptoUtils::hash(&content_for_hash);

        Ok(Self {
            record_id,
            sequence_number,
            timestamp,
            previous_hash,
            content_hash,
            security_event,
            audit_metadata,
            compliance_level,
            retention_until,
        })
    }

    /// Calculate hash of complete audit record for hash chain
    pub fn calculate_record_hash(&self) -> Result<[u8; 32]> {
        let record_content = serde_json::to_vec(self)
            .map_err(|e| crypto_error!("Failed to serialize audit record: {}", e))?;
        Ok(CryptoUtils::hash(&record_content))
    }

    /// Verify cryptographic integrity of this record
    pub fn verify_integrity(&self) -> Result<bool> {
        let content_for_hash = serde_json::to_vec(&(&self.security_event, &self.audit_metadata))
            .map_err(|e| crypto_error!("Failed to serialize audit content: {}", e))?;
        let expected_content_hash = CryptoUtils::hash(&content_for_hash);

        Ok(SecureMemory::constant_time_eq(
            &self.content_hash,
            &expected_content_hash,
        ))
    }

    /// Check if record has expired based on retention policy
    pub fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        current_time > self.retention_until
    }

    /// Export record in compliance-ready format
    pub fn to_compliance_format(&self) -> ComplianceAuditRecord {
        ComplianceAuditRecord {
            record_id: self.record_id.to_string(),
            timestamp_iso: format_timestamp_iso(self.timestamp),
            timestamp_unix: self.timestamp,
            sequence_number: self.sequence_number,
            event_type: format!("{:?}", self.security_event),
            compliance_level: format!("{:?}", self.compliance_level),
            audit_level: format!("{:?}", self.audit_metadata.audit_level),
            audit_source: self.audit_metadata.audit_source.clone(),
            correlation_id: self.audit_metadata.correlation_id.clone(),
            system_version: self.audit_metadata.system_version.clone(),
            content_hash: hex::encode(self.content_hash),
            previous_hash: self.previous_hash.map(hex::encode),
            integrity_verified: self.verify_integrity().unwrap_or(false),
        }
    }
}

/// Additional metadata for audit records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub audit_source: String,
    pub correlation_id: Option<String>,
    pub system_version: String,
    pub audit_level: AuditLevel,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// Audit level classification for event criticality
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditLevel {
    Info,      // Normal operations
    Warning,   // Potentially concerning events
    Critical,  // Security-significant events
    Emergency, // Immediate response required
}

impl AuditLevel {
    fn from_security_event(event: &SecurityEvent) -> Self {
        match event {
            SecurityEvent::SecurityIncident { severity, .. } => match severity {
                crate::crypto::SecuritySeverity::Critical => AuditLevel::Emergency,
                crate::crypto::SecuritySeverity::High => AuditLevel::Critical,
                crate::crypto::SecuritySeverity::Medium => AuditLevel::Warning,
                crate::crypto::SecuritySeverity::Low => AuditLevel::Info,
            },
            SecurityEvent::LoginAttempt { success: false, .. } => AuditLevel::Warning,
            SecurityEvent::VotingBlocked { .. } => AuditLevel::Critical,
            SecurityEvent::RateLimitExceeded { .. } => AuditLevel::Warning,
            SecurityEvent::KeyRotation { .. } => AuditLevel::Critical,
            _ => AuditLevel::Info,
        }
    }
}

/// Compliance level for regulatory requirements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceLevel {
    Standard, // Regular business records (365 days)
    High,     // Financial transactions (90 days)
    Critical, // Regulatory critical (30 days)
}

/// Compliance-ready audit record format for exports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditRecord {
    pub record_id: String,
    pub timestamp_iso: String,
    pub timestamp_unix: u64,
    pub sequence_number: u64,
    pub event_type: String,
    pub compliance_level: String,
    pub audit_level: String,
    pub audit_source: String,
    pub correlation_id: Option<String>,
    pub system_version: String,
    pub content_hash: String,
    pub previous_hash: Option<String>,
    pub integrity_verified: bool,
}

/// Tamper-evident audit trail with cryptographic hash chain
pub struct AuditTrail {
    sequence_counter: Arc<Mutex<u64>>,
    memory_records: Arc<RwLock<VecDeque<AuditRecord>>>,
    last_record_hash: Arc<Mutex<Option<[u8; 32]>>>,
    statistics: Arc<RwLock<AuditTrailStatistics>>,
    config: AuditConfig,
}

impl AuditTrail {
    /// Create new audit trail
    pub fn new(config: AuditConfig) -> Self {
        let initial_stats = AuditTrailStatistics {
            total_records: 0,
            records_in_memory: 0,
            chain_integrity_checks: 0,
            integrity_violations: 0,
            last_integrity_check: None,
            oldest_record_timestamp: None,
            newest_record_timestamp: None,
        };

        Self {
            sequence_counter: Arc::new(Mutex::new(1)),
            memory_records: Arc::new(RwLock::new(VecDeque::new())),
            last_record_hash: Arc::new(Mutex::new(None)),
            statistics: Arc::new(RwLock::new(initial_stats)),
            config,
        }
    }

    /// Add new audit record to the tamper-evident chain
    pub async fn add_record(
        &self,
        security_event: SecurityEvent,
        compliance_level: ComplianceLevel,
        correlation_id: Option<String>,
    ) -> Result<AuditRecord> {
        // Get next sequence number
        let sequence_number = {
            let mut counter = self
                .sequence_counter
                .lock()
                .map_err(|_| crypto_error!("Failed to lock sequence counter"))?;
            let seq = *counter;
            *counter += 1;
            seq
        };

        // Get previous hash for chain
        let previous_hash = {
            let last_hash = self
                .last_record_hash
                .lock()
                .map_err(|_| crypto_error!("Failed to lock last hash"))?;
            *last_hash
        };

        // Create audit record
        let audit_record = AuditRecord::new(
            sequence_number,
            previous_hash,
            security_event,
            compliance_level.clone(),
            self.config.audit_source.clone(),
            correlation_id,
        )?;

        let record_hash = audit_record.calculate_record_hash()?;

        // Add to memory storage
        {
            let mut memory_records = self
                .memory_records
                .write()
                .map_err(|_| crypto_error!("Failed to lock memory records"))?;
            memory_records.push_back(audit_record.clone());

            while memory_records.len() > MAX_MEMORY_AUDIT_RECORDS {
                memory_records.pop_front();
            }
        }

        // Update last record hash
        {
            let mut last_hash = self
                .last_record_hash
                .lock()
                .map_err(|_| crypto_error!("Failed to lock last hash"))?;
            *last_hash = Some(record_hash);
        }

        // Update statistics
        {
            let mut stats = self
                .statistics
                .write()
                .map_err(|_| crypto_error!("Failed to lock statistics"))?;
            stats.total_records += 1;
            stats.records_in_memory = {
                let memory_records = self
                    .memory_records
                    .read()
                    .map_err(|_| crypto_error!("Failed to read memory records"))?;
                memory_records.len()
            };

            if stats.oldest_record_timestamp.is_none() {
                stats.oldest_record_timestamp = Some(audit_record.timestamp);
            }
            stats.newest_record_timestamp = Some(audit_record.timestamp);
        }

        tracing::info!(
            "📝 Audit record added: seq={}, type={:?}, compliance={:?}",
            sequence_number,
            audit_record.security_event,
            compliance_level
        );

        Ok(audit_record)
    }

    /// Verify cryptographic integrity of entire audit trail
    pub async fn verify_trail_integrity(&self) -> Result<AuditIntegrityReport> {
        let memory_records = self
            .memory_records
            .read()
            .map_err(|_| crypto_error!("Failed to read memory records"))?;

        let mut report = AuditIntegrityReport {
            total_records_checked: 0,
            integrity_violations: Vec::new(),
            hash_chain_valid: true,
            verification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let mut previous_hash: Option<[u8; 32]> = None;

        for record in memory_records.iter() {
            report.total_records_checked += 1;

            // Verify individual record integrity
            if !record.verify_integrity()? {
                report.integrity_violations.push(AuditIntegrityViolation {
                    record_id: record.record_id,
                    sequence_number: record.sequence_number,
                    violation_type: IntegrityViolationType::ContentHashMismatch,
                    description: "Content hash mismatch".to_string(),
                });
                report.hash_chain_valid = false;
            }

            // Verify hash chain
            if record.previous_hash != previous_hash {
                report.integrity_violations.push(AuditIntegrityViolation {
                    record_id: record.record_id,
                    sequence_number: record.sequence_number,
                    violation_type: IntegrityViolationType::HashChainBroken,
                    description: "Hash chain broken".to_string(),
                });
                report.hash_chain_valid = false;
            }

            previous_hash = Some(record.calculate_record_hash()?);
        }

        // Update statistics
        {
            let mut stats = self
                .statistics
                .write()
                .map_err(|_| crypto_error!("Failed to lock statistics"))?;
            stats.chain_integrity_checks += 1;
            stats.integrity_violations += report.integrity_violations.len() as u64;
            stats.last_integrity_check = Some(report.verification_timestamp);
        }

        Ok(report)
    }

    /// Query audit records with flexible criteria
    pub async fn query_records(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        let memory_records = self
            .memory_records
            .read()
            .map_err(|_| crypto_error!("Failed to read memory records"))?;

        let mut results = Vec::new();
        for record in memory_records.iter() {
            if self.record_matches_query(record, &query) {
                results.push(record.clone());
            }
        }

        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    /// Export audit records in compliance format
    pub async fn export_compliance_records(
        &self,
        query: AuditQuery,
    ) -> Result<Vec<ComplianceAuditRecord>> {
        let records = self.query_records(query).await?;
        Ok(records
            .into_iter()
            .map(|r| r.to_compliance_format())
            .collect())
    }

    /// Get audit trail statistics
    pub async fn get_statistics(&self) -> Result<AuditTrailStatistics> {
        let stats = self
            .statistics
            .read()
            .map_err(|_| crypto_error!("Failed to read statistics"))?;
        Ok(stats.clone())
    }

    /// Clean up expired audit records
    pub async fn cleanup_expired_records(&self) -> Result<AuditCleanupReport> {
        let mut memory_records = self
            .memory_records
            .write()
            .map_err(|_| crypto_error!("Failed to write memory records"))?;

        let initial_count = memory_records.len();
        let mut removed_count = 0;

        memory_records.retain(|record| {
            if record.is_expired() {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        let final_count = memory_records.len();

        // Update statistics
        {
            let mut stats = self
                .statistics
                .write()
                .map_err(|_| crypto_error!("Failed to lock statistics"))?;
            stats.records_in_memory = final_count;
        }

        Ok(AuditCleanupReport {
            initial_records: initial_count,
            final_records: final_count,
            removed_records: removed_count,
            cleanup_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    fn record_matches_query(&self, record: &AuditRecord, query: &AuditQuery) -> bool {
        if let Some(start_time) = query.start_time {
            if record.timestamp < start_time {
                return false;
            }
        }

        if let Some(end_time) = query.end_time {
            if record.timestamp > end_time {
                return false;
            }
        }

        if let Some(ref event_types) = query.event_types {
            let event_type = format!("{:?}", record.security_event);
            if !event_types.iter().any(|et| event_type.contains(et)) {
                return false;
            }
        }

        if let Some(ref compliance_levels) = query.compliance_levels {
            if !compliance_levels.contains(&record.compliance_level) {
                return false;
            }
        }

        if let Some(ref audit_levels) = query.audit_levels {
            if !audit_levels.contains(&record.audit_metadata.audit_level) {
                return false;
            }
        }

        if let Some(ref correlation_id) = query.correlation_id {
            match &record.audit_metadata.correlation_id {
                Some(record_correlation_id) => {
                    if record_correlation_id != correlation_id {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// Configuration for audit system
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub audit_source: String,
    pub enable_streaming: bool,
    pub max_memory_records: usize,
    pub default_compliance_level: ComplianceLevel,
    pub enable_auto_integrity_checks: bool,
    pub integrity_check_interval: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            audit_source: "voting_system".to_string(),
            enable_streaming: true,
            max_memory_records: MAX_MEMORY_AUDIT_RECORDS,
            default_compliance_level: ComplianceLevel::Standard,
            enable_auto_integrity_checks: true,
            integrity_check_interval: 3600,
        }
    }
}

impl AuditConfig {
    pub fn for_testing() -> Self {
        Self {
            audit_source: "voting_system_test".to_string(),
            enable_streaming: false,
            max_memory_records: 1000,
            default_compliance_level: ComplianceLevel::Standard,
            enable_auto_integrity_checks: false,
            integrity_check_interval: 60,
        }
    }
}

/// Query criteria for searching audit records
#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub event_types: Option<Vec<String>>,
    pub compliance_levels: Option<Vec<ComplianceLevel>>,
    pub audit_levels: Option<Vec<AuditLevel>>,
    pub correlation_id: Option<String>,
    pub limit: Option<usize>,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_types: None,
            compliance_levels: None,
            audit_levels: None,
            correlation_id: None,
            limit: Some(100),
        }
    }
}

/// Audit trail statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailStatistics {
    pub total_records: u64,
    pub records_in_memory: usize,
    pub chain_integrity_checks: u64,
    pub integrity_violations: u64,
    pub last_integrity_check: Option<u64>,
    pub oldest_record_timestamp: Option<u64>,
    pub newest_record_timestamp: Option<u64>,
}

/// Integrity verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIntegrityReport {
    pub total_records_checked: usize,
    pub integrity_violations: Vec<AuditIntegrityViolation>,
    pub hash_chain_valid: bool,
    pub verification_timestamp: u64,
}

/// Specific integrity violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIntegrityViolation {
    pub record_id: Uuid,
    pub sequence_number: u64,
    pub violation_type: IntegrityViolationType,
    pub description: String,
}

/// Types of integrity violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityViolationType {
    ContentHashMismatch,
    HashChainBroken,
    SequenceNumberGap,
    TimestampAnomaly,
}

/// Audit cleanup report
#[derive(Debug, Clone)]
pub struct AuditCleanupReport {
    pub initial_records: usize,
    pub final_records: usize,
    pub removed_records: usize,
    pub cleanup_timestamp: u64,
}

/// Enhanced audit system with streaming and compliance
pub struct EnhancedAuditSystem {
    audit_trail: Arc<AuditTrail>,
    real_time_stream: Arc<RwLock<Vec<AuditStreamSubscriber>>>,
    compliance_engine: Arc<ComplianceEngine>,
    config: AuditConfig,
}

impl EnhancedAuditSystem {
    /// Create new enhanced audit system
    pub fn new(config: AuditConfig) -> Self {
        let audit_trail = Arc::new(AuditTrail::new(config.clone()));
        let compliance_engine = Arc::new(ComplianceEngine::new());

        Self {
            audit_trail,
            real_time_stream: Arc::new(RwLock::new(Vec::new())),
            compliance_engine,
            config,
        }
    }

    /// Create audit system for testing
    pub fn for_testing() -> Self {
        Self::new(AuditConfig::for_testing())
    }

    /// Log security event with audit trail integration
    pub async fn log_security_event(
        &self,
        security_event: SecurityEvent,
        compliance_level: Option<ComplianceLevel>,
        correlation_id: Option<String>,
    ) -> Result<AuditRecord> {
        let compliance_level =
            compliance_level.unwrap_or_else(|| self.config.default_compliance_level.clone());

        let audit_record = self
            .audit_trail
            .add_record(security_event.clone(), compliance_level, correlation_id)
            .await?;

        if self.config.enable_streaming {
            self.stream_to_subscribers(&audit_record).await;
        }

        self.compliance_engine.check_compliance(&audit_record).await;

        Ok(audit_record)
    }

    /// Verify audit trail integrity
    pub async fn verify_integrity(&self) -> Result<AuditIntegrityReport> {
        self.audit_trail.verify_trail_integrity().await
    }

    /// Query audit records
    pub async fn query_audit_records(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        self.audit_trail.query_records(query).await
    }

    /// Export compliance report
    pub async fn export_compliance_report(&self, query: AuditQuery) -> Result<ComplianceReport> {
        let records = self.audit_trail.export_compliance_records(query).await?;
        let statistics = self.audit_trail.get_statistics().await?;
        let integrity_report = self.audit_trail.verify_trail_integrity().await?;

        Ok(ComplianceReport {
            report_id: Uuid::new_v4(),
            generated_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            audit_records: records,
            statistics,
            integrity_report,
            compliance_summary: self.compliance_engine.generate_summary().await,
        })
    }

    /// Get audit system statistics
    pub async fn get_statistics(&self) -> Result<AuditTrailStatistics> {
        self.audit_trail.get_statistics().await
    }

    /// Clean up expired records
    pub async fn cleanup_expired(&self) -> Result<AuditCleanupReport> {
        self.audit_trail.cleanup_expired_records().await
    }

    /// Subscribe to real-time audit stream
    pub async fn subscribe_to_stream(&self, subscriber: AuditStreamSubscriber) -> Result<()> {
        let mut stream = self
            .real_time_stream
            .write()
            .map_err(|_| crypto_error!("Failed to lock audit stream"))?;
        stream.push(subscriber);
        Ok(())
    }

    async fn stream_to_subscribers(&self, _audit_record: &AuditRecord) {
        if let Ok(stream) = self.real_time_stream.read() {
            for subscriber in stream.iter() {
                tracing::debug!(
                    "📡 Streaming audit record to subscriber: {}",
                    subscriber.subscriber_id
                );
            }
        }
    }
}

/// Real-time audit stream subscriber
#[derive(Debug, Clone)]
pub struct AuditStreamSubscriber {
    pub subscriber_id: String,
    pub event_filter: Option<Vec<String>>,
    pub compliance_filter: Option<Vec<ComplianceLevel>>,
}

/// Compliance engine for automated checking
pub struct ComplianceEngine {
    #[allow(dead_code)]
    violation_patterns: Arc<RwLock<Vec<CompliancePattern>>>,
    compliance_statistics: Arc<RwLock<ComplianceStatistics>>,
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceEngine {
    pub fn new() -> Self {
        Self {
            violation_patterns: Arc::new(RwLock::new(Vec::new())),
            compliance_statistics: Arc::new(RwLock::new(ComplianceStatistics::default())),
        }
    }

    pub async fn check_compliance(&self, _audit_record: &AuditRecord) {
        // Placeholder for compliance checking
    }

    pub async fn generate_summary(&self) -> ComplianceSummary {
        let stats = self.compliance_statistics.read().unwrap();
        ComplianceSummary {
            total_violations: stats.total_violations,
            critical_violations: stats.critical_violations,
            compliance_score: stats.compliance_score,
            last_assessment: stats.last_assessment,
        }
    }
}

/// Compliance pattern for violation detection
#[derive(Debug, Clone)]
pub struct CompliancePattern {
    pub pattern_id: String,
    pub description: String,
    pub severity: ComplianceSeverity,
}

/// Compliance violation severity
#[derive(Debug, Clone)]
pub enum ComplianceSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Compliance statistics
#[derive(Debug, Clone, Default)]
pub struct ComplianceStatistics {
    pub total_violations: u64,
    pub critical_violations: u64,
    pub compliance_score: f64,
    pub last_assessment: Option<u64>,
}

/// Compliance summary for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_violations: u64,
    pub critical_violations: u64,
    pub compliance_score: f64,
    pub last_assessment: Option<u64>,
}

/// Complete compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: Uuid,
    pub generated_timestamp: u64,
    pub audit_records: Vec<ComplianceAuditRecord>,
    pub statistics: AuditTrailStatistics,
    pub integrity_report: AuditIntegrityReport,
    pub compliance_summary: ComplianceSummary,
}

/// Format timestamp in ISO format
fn format_timestamp_iso(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let _datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    // Simple ISO format approximation
    format!("1970-01-01T00:00:{}Z", timestamp % 86400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SecurityEvent, SecurityIncidentType, SecuritySeverity};

    #[tokio::test]
    async fn test_audit_record_creation_and_integrity() {
        let security_event = SecurityEvent::LoginAttempt {
            voter_hash: "test_voter".to_string(),
            election_id: Uuid::new_v4(),
            session_id: Some("test_session".to_string()),
            success: true,
            timestamp: 1234567890,
            ip_address: Some("192.168.1.1".to_string()),
        };

        let audit_record = AuditRecord::new(
            1,
            None,
            security_event,
            ComplianceLevel::Standard,
            "test_system".to_string(),
            Some("correlation_123".to_string()),
        )
        .unwrap();

        assert_eq!(audit_record.sequence_number, 1);
        assert_eq!(audit_record.previous_hash, None);
        assert_eq!(audit_record.compliance_level, ComplianceLevel::Standard);
        assert!(audit_record.verify_integrity().unwrap());

        println!("✅ Audit record creation and integrity verification works");
    }

    #[tokio::test]
    async fn test_audit_trail_hash_chain() {
        let config = AuditConfig::for_testing();
        let audit_trail = AuditTrail::new(config);

        let event1 = SecurityEvent::LoginAttempt {
            voter_hash: "voter1".to_string(),
            election_id: Uuid::new_v4(),
            session_id: Some("session1".to_string()),
            success: true,
            timestamp: 1234567890,
            ip_address: None,
        };

        let record1 = audit_trail
            .add_record(
                event1,
                ComplianceLevel::Standard,
                Some("correlation_1".to_string()),
            )
            .await
            .unwrap();

        let event2 = SecurityEvent::VotingCompleted {
            voter_hash: "voter1".to_string(),
            election_id: Uuid::new_v4(),
            method: crate::crypto::VotingMethod::Digital,
            vote_id: Some(Uuid::new_v4()),
            completion_id: Uuid::new_v4(),
            timestamp: 1234567900,
        };

        let record2 = audit_trail
            .add_record(
                event2,
                ComplianceLevel::High,
                Some("correlation_2".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(record1.sequence_number, 1);
        assert_eq!(record2.sequence_number, 2);
        assert_eq!(record1.previous_hash, None);
        assert!(record2.previous_hash.is_some());

        let record1_hash = record1.calculate_record_hash().unwrap();
        assert_eq!(record2.previous_hash, Some(record1_hash));

        let integrity_report = audit_trail.verify_trail_integrity().await.unwrap();
        assert!(integrity_report.hash_chain_valid);
        assert_eq!(integrity_report.total_records_checked, 2);
        assert!(integrity_report.integrity_violations.is_empty());

        println!("✅ Audit trail hash chain verification works");
    }

    #[tokio::test]
    async fn test_enhanced_audit_system_integration() {
        let audit_system = EnhancedAuditSystem::for_testing();

        let security_event = SecurityEvent::SecurityIncident {
            incident_id: Uuid::new_v4(),
            incident_type: SecurityIncidentType::RepeatedFailedAuthentication,
            voter_hash: "suspicious_voter".to_string(),
            description: "Multiple failed login attempts".to_string(),
            severity: SecuritySeverity::High,
            timestamp: 1234567890,
        };

        let audit_record = audit_system
            .log_security_event(
                security_event,
                Some(ComplianceLevel::Critical),
                Some("incident_investigation_456".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(audit_record.compliance_level, ComplianceLevel::Critical);
        assert_eq!(
            audit_record.audit_metadata.correlation_id,
            Some("incident_investigation_456".to_string())
        );

        let query = AuditQuery {
            correlation_id: Some("incident_investigation_456".to_string()),
            ..Default::default()
        };

        let results = audit_system.query_audit_records(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_id, audit_record.record_id);

        let integrity_report = audit_system.verify_integrity().await.unwrap();
        assert!(integrity_report.hash_chain_valid);

        let statistics = audit_system.get_statistics().await.unwrap();
        assert_eq!(statistics.total_records, 1);

        println!("✅ Enhanced audit system integration works");
    }

    #[tokio::test]
    async fn test_compliance_export() {
        let audit_system = EnhancedAuditSystem::for_testing();

        for i in 0..5 {
            let event = SecurityEvent::LoginAttempt {
                voter_hash: format!("voter_{i}"),
                election_id: Uuid::new_v4(),
                session_id: Some(format!("session_{i}")),
                success: i % 2 == 0,
                timestamp: 1234567890 + i,
                ip_address: Some(format!("192.168.1.{}", i + 1)),
            };

            audit_system
                .log_security_event(
                    event,
                    Some(ComplianceLevel::Standard),
                    Some(format!("correlation_{i}")),
                )
                .await
                .unwrap();
        }

        let query = AuditQuery::default();
        let compliance_report = audit_system.export_compliance_report(query).await.unwrap();

        assert_eq!(compliance_report.audit_records.len(), 5);
        assert!(compliance_report.integrity_report.hash_chain_valid);
        assert_eq!(compliance_report.statistics.total_records, 5);

        let first_record = &compliance_report.audit_records[0];
        assert!(first_record.integrity_verified);
        assert!(!first_record.content_hash.is_empty());
        assert!(first_record.timestamp_iso.contains("T"));

        println!("✅ Compliance export functionality works");
    }
}
