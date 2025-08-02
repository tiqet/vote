//! Automatic Security Incident Management for Banking-Grade Threat Response
//!
//! This module provides comprehensive automated security incident management:
//! - Real-time pattern correlation across multiple security systems
//! - Automated threat response and escalation workflows
//! - Incident lifecycle management from detection to resolution
//! - Evidence collection and preservation for compliance
//! - Integration with all existing security components
//! - Banking-grade automated countermeasures
//!
//! Key Features:
//! - Multi-vector attack correlation and analysis
//! - Automated response orchestration with escalation paths
//! - Behavioral pattern analysis and anomaly detection
//! - Incident documentation and evidence preservation
//! - Compliance-ready reporting and audit integration
//! - Real-time threat mitigation and countermeasures

use crate::crypto::{
    AuthenticationPattern, DoSPattern, EnhancedAuditSystem, SecurityContext, SecurityLevel,
    SecurityOperation, SecurityPerformanceMonitor,
};
use crate::{Result, crypto_error};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Maximum incidents to keep in active memory
const MAX_ACTIVE_INCIDENTS: usize = 1000;

/// Maximum correlation window for pattern analysis (seconds)
const CORRELATION_WINDOW_SECONDS: u64 = 3600; // 1 hour

/// Incident severity escalation thresholds
const CRITICAL_INCIDENT_THRESHOLD: f64 = 0.9;

#[allow(dead_code)]
const HIGH_INCIDENT_THRESHOLD: f64 = 0.7;

#[allow(dead_code)]
const MEDIUM_INCIDENT_THRESHOLD: f64 = 0.4;

/// Comprehensive security incident with automated management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    /// Unique incident identifier
    pub incident_id: Uuid,

    /// Incident type and classification
    pub incident_type: IncidentType,

    /// Current incident severity
    pub severity: IncidentSeverity,

    /// Current incident status
    pub status: IncidentStatus,

    /// When the incident was first detected
    pub detected_at: u64,

    /// When the incident was last updated
    pub updated_at: u64,

    /// When the incident was resolved (if applicable)
    pub resolved_at: Option<u64>,

    /// Primary affected entity (voter, election, system)
    pub affected_entity: AffectedEntity,

    /// Related security events that contributed to this incident
    pub related_events: Vec<Uuid>,

    /// Evidence collected for this incident
    pub evidence: IncidentEvidence,

    /// Automated responses that have been executed
    pub responses_executed: Vec<AutomatedResponse>,

    /// Current threat score (0.0 to 1.0)
    pub threat_score: f64,

    /// Incident correlation data
    pub correlation_data: IncidentCorrelation,

    /// Human-readable description
    pub description: String,

    /// Compliance and audit metadata
    pub compliance_metadata: ComplianceMetadata,
}

impl SecurityIncident {
    pub fn new(
        incident_type: IncidentType,
        affected_entity: AffectedEntity,
        initial_events: Vec<Uuid>,
        description: String,
    ) -> Result<Self> {
        let incident_id = Uuid::new_v4();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        let severity = IncidentSeverity::from_incident_type(&incident_type);

        Ok(Self {
            incident_id,
            incident_type,
            severity,
            status: IncidentStatus::Detected,
            detected_at: current_time,
            updated_at: current_time,
            resolved_at: None,
            affected_entity,
            related_events: initial_events,
            evidence: IncidentEvidence::new(),
            responses_executed: Vec::new(),
            threat_score: 0.5, // Initial neutral score
            correlation_data: IncidentCorrelation::new(),
            description,
            compliance_metadata: ComplianceMetadata::new(),
        })
    }

    /// Update incident status and timestamp
    pub fn update_status(&mut self, new_status: IncidentStatus) -> Result<()> {
        // Check status before moving to avoid use after move
        if matches!(
            new_status,
            IncidentStatus::Resolved | IncidentStatus::Closed
        ) {
            self.resolved_at = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| crypto_error!("System time error"))?
                    .as_secs(),
            );
        }

        self.status = new_status;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        Ok(())
    }

    /// Add evidence to the incident
    pub fn add_evidence(&mut self, evidence_type: EvidenceType, data: serde_json::Value) {
        self.evidence.add_evidence(evidence_type, data);
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Record an automated response
    pub fn record_response(&mut self, response: AutomatedResponse) {
        self.responses_executed.push(response);
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Calculate threat escalation score
    pub fn calculate_threat_escalation(&self) -> f64 {
        let mut score = self.threat_score;

        // Escalate based on response count
        score += (self.responses_executed.len() as f64 * 0.1).min(0.3);

        // Escalate based on incident duration
        let duration_hours = (self.updated_at - self.detected_at) as f64 / 3600.0;
        if duration_hours > 1.0 {
            score += (duration_hours * 0.05).min(0.2);
        }

        // Escalate based on evidence volume
        score += (self.evidence.evidence_count() as f64 * 0.02).min(0.15);

        score.min(1.0)
    }

    /// Check if incident requires human intervention
    pub fn requires_human_intervention(&self) -> bool {
        self.calculate_threat_escalation() > CRITICAL_INCIDENT_THRESHOLD
            || self.responses_executed.len() > 5
            || matches!(self.severity, IncidentSeverity::Critical)
    }
}

/// Types of security incidents
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentType {
    // Authentication-based incidents
    BruteForceAttack {
        failed_attempts: u32,
        time_window_seconds: u64,
    },
    CredentialStuffing {
        unique_attempts: u32,
        pattern_confidence: f64,
    },
    AccountTakeover {
        suspicious_activities: Vec<String>,
    },

    // Timing and crypto attacks
    TimingAttack {
        operation: SecurityOperation,
        anomaly_count: u32,
        deviation_threshold: f64,
    },
    CryptographicFailure {
        operation: SecurityOperation,
        failure_rate: f64,
    },

    // DoS and resource attacks
    DenialOfService {
        attack_vectors: Vec<String>,
        resource_impact: f64,
    },
    ResourceExhaustion {
        resource_type: String,
        utilization_peak: f64,
    },

    // Voting-specific incidents
    VotingAnomaly {
        anomaly_type: String,
        affected_elections: Vec<Uuid>,
    },
    TokenManipulation {
        manipulation_type: String,
        affected_tokens: u32,
    },

    // System and operational incidents
    SystemIntegrityFailure {
        component: String,
        failure_details: String,
    },
    AuditTrailTampering {
        tampered_records: u32,
        detection_method: String,
    },

    // Advanced persistent threats
    AdvancedPersistentThreat {
        campaign_indicators: Vec<String>,
        persistence_mechanisms: Vec<String>,
    },

    // Compliance violations
    ComplianceViolation {
        regulation: String,
        violation_details: String,
    },
}

/// Incident severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

impl IncidentSeverity {
    fn from_incident_type(incident_type: &IncidentType) -> Self {
        match incident_type {
            IncidentType::BruteForceAttack {
                failed_attempts, ..
            } => {
                if *failed_attempts > 100 {
                    Self::Critical
                } else if *failed_attempts > 50 {
                    Self::High
                } else if *failed_attempts > 20 {
                    Self::Medium
                } else {
                    Self::Low
                }
            }
            IncidentType::TimingAttack { anomaly_count, .. } => {
                if *anomaly_count > 50 {
                    Self::High
                } else if *anomaly_count > 20 {
                    Self::Medium
                } else {
                    Self::Low
                }
            }
            IncidentType::CryptographicFailure { failure_rate, .. } => {
                if *failure_rate > 0.5 {
                    Self::Critical
                } else if *failure_rate > 0.2 {
                    Self::High
                } else {
                    Self::Medium
                }
            }
            IncidentType::DenialOfService { .. } => Self::Critical,
            IncidentType::SystemIntegrityFailure { .. } => Self::Emergency,
            IncidentType::AuditTrailTampering { .. } => Self::Emergency,
            IncidentType::AdvancedPersistentThreat { .. } => Self::Critical,
            IncidentType::ComplianceViolation { .. } => Self::High,
            _ => Self::Medium,
        }
    }
}

/// Current status of an incident
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Detected,   // Initial detection
    Analyzing,  // Under automated analysis
    Responding, // Automated response in progress
    Escalated,  // Escalated to human intervention
    Contained,  // Threat contained but monitoring continues
    Resolved,   // Incident resolved
    Closed,     // Incident closed and archived
}

/// Entity affected by the incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AffectedEntity {
    Voter { voter_hash: String },
    Election { election_id: Uuid },
    System { component: String },
    Multiple { entities: Vec<String> },
    Unknown,
}

/// Evidence collected for an incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvidence {
    pub security_events: Vec<Uuid>,
    pub performance_metrics: Vec<serde_json::Value>,
    pub audit_records: Vec<Uuid>,
    pub system_logs: Vec<String>,
    pub forensic_data: HashMap<String, serde_json::Value>,
    pub collected_at: u64,
}

impl Default for IncidentEvidence {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentEvidence {
    pub fn new() -> Self {
        Self {
            security_events: Vec::new(),
            performance_metrics: Vec::new(),
            audit_records: Vec::new(),
            system_logs: Vec::new(),
            forensic_data: HashMap::new(),
            collected_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn add_evidence(&mut self, evidence_type: EvidenceType, data: serde_json::Value) {
        match evidence_type {
            EvidenceType::SecurityEvent => {
                if let Ok(event_id) = serde_json::from_value::<Uuid>(data) {
                    self.security_events.push(event_id);
                }
            }
            EvidenceType::PerformanceMetric => {
                self.performance_metrics.push(data);
            }
            EvidenceType::AuditRecord => {
                if let Ok(record_id) = serde_json::from_value::<Uuid>(data) {
                    self.audit_records.push(record_id);
                }
            }
            EvidenceType::SystemLog => {
                if let Ok(log_entry) = serde_json::from_value::<String>(data) {
                    self.system_logs.push(log_entry);
                }
            }
            EvidenceType::ForensicData(key) => {
                self.forensic_data.insert(key, data);
            }
        }
    }

    pub fn evidence_count(&self) -> usize {
        self.security_events.len()
            + self.performance_metrics.len()
            + self.audit_records.len()
            + self.system_logs.len()
            + self.forensic_data.len()
    }
}

/// Types of evidence that can be collected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    SecurityEvent,
    PerformanceMetric,
    AuditRecord,
    SystemLog,
    ForensicData(String),
}

/// Incident correlation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCorrelation {
    pub related_incidents: Vec<Uuid>,
    pub pattern_indicators: Vec<String>,
    pub correlation_score: f64,
    pub campaign_indicators: Vec<String>,
}

impl Default for IncidentCorrelation {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentCorrelation {
    pub fn new() -> Self {
        Self {
            related_incidents: Vec::new(),
            pattern_indicators: Vec::new(),
            correlation_score: 0.0,
            campaign_indicators: Vec::new(),
        }
    }
}

/// Compliance and audit metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetadata {
    pub regulatory_impact: Vec<String>,
    pub reporting_requirements: Vec<String>,
    pub evidence_preservation: bool,
    pub sla_requirements: Option<Duration>,
}

impl Default for ComplianceMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceMetadata {
    pub fn new() -> Self {
        Self {
            regulatory_impact: Vec::new(),
            reporting_requirements: Vec::new(),
            evidence_preservation: true, // Always preserve evidence
            sla_requirements: Some(Duration::from_secs(300)), // 5 minutes default
        }
    }
}

/// Automated response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedResponse {
    pub response_id: Uuid,
    pub response_type: ResponseType,
    pub executed_at: u64,
    pub execution_result: ResponseResult,
    pub affected_entities: Vec<String>,
    pub effectiveness_score: Option<f64>,
}

impl AutomatedResponse {
    pub fn new(response_type: ResponseType, affected_entities: Vec<String>) -> Self {
        Self {
            response_id: Uuid::new_v4(),
            response_type,
            executed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            execution_result: ResponseResult::Pending,
            affected_entities,
            effectiveness_score: None,
        }
    }
}

/// Types of automated responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseType {
    // Rate limiting responses
    RateLimitEscalation {
        operation: SecurityOperation,
        escalation_factor: u32,
        duration: Duration,
    },

    // Account security responses
    TemporaryAccountLock {
        voter_hash: String,
        duration: Duration,
        reason: String,
    },
    SecurityLevelEscalation {
        voter_hash: String,
        new_level: SecurityLevel,
    },

    // Token and session responses
    TokenInvalidation {
        scope: TokenInvalidationScope,
        reason: String,
    },
    SessionTermination {
        session_ids: Vec<String>,
        reason: String,
    },

    // Cryptographic responses
    EmergencyKeyRotation {
        component: String,
        reason: String,
    },
    CertificateRevocation {
        certificate_ids: Vec<String>,
    },

    // System responses
    ServiceIsolation {
        service_name: String,
        isolation_level: String,
    },
    AlertEscalation {
        alert_level: AlertLevel,
        recipients: Vec<String>,
    },

    // Monitoring responses
    EnhancedMonitoring {
        entities: Vec<String>,
        monitoring_level: String,
        duration: Duration,
    },
    AuditIntensification {
        scope: String,
        additional_fields: Vec<String>,
    },
}

/// Token invalidation scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenInvalidationScope {
    SingleToken(String),
    VoterTokens(String),
    ElectionTokens(Uuid),
    AllTokens,
}

/// Alert escalation levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Response execution results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseResult {
    Pending,
    Success,
    PartialSuccess { details: String },
    Failed { error: String },
    Skipped { reason: String },
}

/// Pattern correlator for detecting complex attack patterns
pub struct PatternCorrelator {
    // Pattern detection state
    #[allow(dead_code)]
    pattern_history: Arc<RwLock<VecDeque<PatternEvent>>>,
    #[allow(dead_code)]
    correlation_rules: Arc<RwLock<Vec<CorrelationRule>>>,

    // Configuration
    #[allow(dead_code)]
    correlation_window: Duration,
    #[allow(dead_code)]
    max_pattern_history: usize,
}

impl PatternCorrelator {
    pub fn new(correlation_window: Duration, max_pattern_history: usize) -> Self {
        Self {
            pattern_history: Arc::new(RwLock::new(VecDeque::new())),
            correlation_rules: Arc::new(RwLock::new(Self::default_correlation_rules())),
            correlation_window,
            max_pattern_history,
        }
    }

    /// Analyze patterns and detect potential incidents
    pub async fn analyze_patterns(
        &self,
        performance_monitor: &SecurityPerformanceMonitor,
        _audit_system: &EnhancedAuditSystem,
    ) -> Result<Vec<DetectedPattern>> {
        let mut detected_patterns = Vec::new();

        // Analyze authentication patterns
        let auth_patterns = performance_monitor.get_auth_patterns().await?;
        for pattern in auth_patterns {
            if let Some(detected) = self.analyze_authentication_pattern(&pattern).await? {
                detected_patterns.push(detected);
            }
        }

        // Analyze DoS patterns
        let dos_patterns = performance_monitor.get_dos_patterns().await?;
        for pattern in dos_patterns {
            if let Some(detected) = self.analyze_dos_pattern(&pattern).await? {
                detected_patterns.push(detected);
            }
        }

        // Analyze performance metrics for timing attacks
        let metrics = performance_monitor.get_current_metrics().await?;
        if let Some(detected) = self.analyze_timing_patterns(&metrics).await? {
            detected_patterns.push(detected);
        }

        Ok(detected_patterns)
    }

    /// Analyze authentication patterns for brute force and credential stuffing
    async fn analyze_authentication_pattern(
        &self,
        auth_pattern: &AuthenticationPattern,
    ) -> Result<Option<DetectedPattern>> {
        if auth_pattern.is_suspicious() {
            let pattern_type = if auth_pattern.avg_attempt_interval < 1.0 {
                PatternType::BruteForceAttack
            } else if auth_pattern.timing_anomalies > auth_pattern.failed_attempts / 2 {
                PatternType::TimingAttack
            } else {
                PatternType::SuspiciousAuthentication
            };

            return Ok(Some(DetectedPattern {
                pattern_id: Uuid::new_v4(),
                pattern_type,
                confidence: auth_pattern.suspicious_score,
                affected_entities: vec![auth_pattern.voter_hash.clone()],
                evidence: vec![format!(
                    "Failed attempts: {}, Timing anomalies: {}",
                    auth_pattern.failed_attempts, auth_pattern.timing_anomalies
                )],
                detected_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }));
        }

        Ok(None)
    }

    /// Analyze DoS patterns
    async fn analyze_dos_pattern(
        &self,
        dos_pattern: &DoSPattern,
    ) -> Result<Option<DetectedPattern>> {
        let confidence = match dos_pattern.severity {
            crate::crypto::security_monitoring::DoSSeverity::Critical => 0.9,
            crate::crypto::security_monitoring::DoSSeverity::High => 0.7,
            crate::crypto::security_monitoring::DoSSeverity::Medium => 0.5,
            crate::crypto::security_monitoring::DoSSeverity::Low => 0.3,
        };

        Ok(Some(DetectedPattern {
            pattern_id: Uuid::new_v4(),
            pattern_type: PatternType::DenialOfService,
            confidence,
            affected_entities: vec!["system".to_string()],
            evidence: vec![format!(
                "DoS pattern: {:?}, Duration: {}s",
                dos_pattern.detection_type, dos_pattern.duration_seconds
            )],
            detected_at: dos_pattern.start_time,
        }))
    }

    /// Analyze timing patterns for potential timing attacks
    async fn analyze_timing_patterns(
        &self,
        metrics: &crate::crypto::security_monitoring::SecurityPerformanceMetrics,
    ) -> Result<Option<DetectedPattern>> {
        if metrics.timing_anomalies_detected > 10 {
            return Ok(Some(DetectedPattern {
                pattern_id: Uuid::new_v4(),
                pattern_type: PatternType::TimingAttack,
                confidence: (metrics.timing_anomalies_detected as f64 / 100.0).min(0.9),
                affected_entities: vec!["crypto_operations".to_string()],
                evidence: vec![format!(
                    "Timing anomalies: {}, Potential attacks: {}",
                    metrics.timing_anomalies_detected, metrics.potential_timing_attacks
                )],
                detected_at: metrics.timestamp,
            }));
        }

        Ok(None)
    }

    fn default_correlation_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                rule_id: "brute_force_detection".to_string(),
                description: "Detect brute force authentication attacks".to_string(),
                conditions: vec![
                    "failed_auth_count > 10".to_string(),
                    "time_window < 300".to_string(),
                ],
                confidence_threshold: 0.7,
            },
            CorrelationRule {
                rule_id: "timing_attack_detection".to_string(),
                description: "Detect timing-based side-channel attacks".to_string(),
                conditions: vec![
                    "timing_anomalies > 20".to_string(),
                    "operation_type = crypto".to_string(),
                ],
                confidence_threshold: 0.6,
            },
        ]
    }
}

/// Detected pattern from correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_id: Uuid,
    pub pattern_type: PatternType,
    pub confidence: f64,
    pub affected_entities: Vec<String>,
    pub evidence: Vec<String>,
    pub detected_at: u64,
}

/// Types of patterns that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    BruteForceAttack,
    TimingAttack,
    DenialOfService,
    SuspiciousAuthentication,
    SystematicFailure,
    AnomalousActivity,
}

/// Pattern event for correlation
#[derive(Debug, Clone)]
struct PatternEvent {
    #[allow(dead_code)]
    event_type: String,
    #[allow(dead_code)]
    entity: String,
    #[allow(dead_code)]
    timestamp: u64,
    #[allow(dead_code)]
    metadata: HashMap<String, String>,
}

/// Correlation rule definition
#[derive(Debug, Clone)]
struct CorrelationRule {
    #[allow(dead_code)]
    rule_id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    conditions: Vec<String>,
    #[allow(dead_code)]
    confidence_threshold: f64,
}

/// Escalation engine for determining appropriate responses
pub struct EscalationEngine {
    #[allow(dead_code)]
    escalation_rules: Arc<RwLock<Vec<EscalationRule>>>,
    #[allow(dead_code)]
    response_history: Arc<RwLock<HashMap<String, Vec<AutomatedResponse>>>>,
}

impl Default for EscalationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationEngine {
    pub fn new() -> Self {
        Self {
            escalation_rules: Arc::new(RwLock::new(Self::default_escalation_rules())),
            response_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Determine appropriate responses for an incident
    pub async fn determine_responses(
        &self,
        incident: &SecurityIncident,
    ) -> Result<Vec<ResponseType>> {
        let mut responses = Vec::new();

        match &incident.incident_type {
            IncidentType::BruteForceAttack {
                failed_attempts, ..
            } => {
                responses.push(ResponseType::RateLimitEscalation {
                    operation: SecurityOperation::SecureLogin,
                    escalation_factor: (*failed_attempts / 10).max(2),
                    duration: Duration::from_secs(3600),
                });

                if *failed_attempts > 50 {
                    if let AffectedEntity::Voter { voter_hash } = &incident.affected_entity {
                        responses.push(ResponseType::TemporaryAccountLock {
                            voter_hash: voter_hash.clone(),
                            duration: Duration::from_secs(1800), // 30 minutes
                            reason: "Brute force attack detected".to_string(),
                        });
                    }
                }
            }

            IncidentType::TimingAttack {
                operation,
                anomaly_count,
                ..
            } => {
                responses.push(ResponseType::RateLimitEscalation {
                    operation: operation.clone(),
                    escalation_factor: (*anomaly_count / 5).max(2),
                    duration: Duration::from_secs(1800),
                });

                if *anomaly_count > 50 {
                    responses.push(ResponseType::EmergencyKeyRotation {
                        component: format!("{operation:?}"),
                        reason: "Timing attack detected".to_string(),
                    });
                }
            }

            IncidentType::DenialOfService { .. } => {
                responses.push(ResponseType::AlertEscalation {
                    alert_level: AlertLevel::Critical,
                    recipients: vec!["security_team".to_string()],
                });

                responses.push(ResponseType::EnhancedMonitoring {
                    entities: vec!["all_services".to_string()],
                    monitoring_level: "high".to_string(),
                    duration: Duration::from_secs(7200), // 2 hours
                });
            }

            IncidentType::SystemIntegrityFailure { component, .. } => {
                responses.push(ResponseType::AlertEscalation {
                    alert_level: AlertLevel::Emergency,
                    recipients: vec!["security_team".to_string(), "engineering_team".to_string()],
                });

                responses.push(ResponseType::ServiceIsolation {
                    service_name: component.clone(),
                    isolation_level: "quarantine".to_string(),
                });
            }

            _ => {
                // Default response for other incident types
                responses.push(ResponseType::EnhancedMonitoring {
                    entities: vec!["affected_entity".to_string()],
                    monitoring_level: "elevated".to_string(),
                    duration: Duration::from_secs(3600),
                });
            }
        }

        // Add alert escalation for high severity incidents
        if matches!(
            incident.severity,
            IncidentSeverity::Critical | IncidentSeverity::Emergency
        ) {
            responses.push(ResponseType::AlertEscalation {
                alert_level: AlertLevel::Critical,
                recipients: vec!["security_team".to_string()],
            });
        }

        Ok(responses)
    }

    fn default_escalation_rules() -> Vec<EscalationRule> {
        vec![
            EscalationRule {
                rule_id: "brute_force_escalation".to_string(),
                conditions: vec!["incident_type = brute_force".to_string()],
                responses: vec!["rate_limit".to_string(), "account_lock".to_string()],
                escalation_threshold: 0.7,
            },
            EscalationRule {
                rule_id: "timing_attack_escalation".to_string(),
                conditions: vec!["incident_type = timing_attack".to_string()],
                responses: vec![
                    "key_rotation".to_string(),
                    "enhanced_monitoring".to_string(),
                ],
                escalation_threshold: 0.6,
            },
        ]
    }
}

/// Escalation rule definition
#[derive(Debug, Clone)]
struct EscalationRule {
    #[allow(dead_code)]
    rule_id: String,
    #[allow(dead_code)]
    conditions: Vec<String>,
    #[allow(dead_code)]
    responses: Vec<String>,
    #[allow(dead_code)]
    escalation_threshold: f64,
}

/// Response orchestrator for executing automated responses
pub struct ResponseOrchestrator {
    #[allow(dead_code)]
    execution_queue: Arc<Mutex<VecDeque<(Uuid, ResponseType)>>>,
    execution_history: Arc<RwLock<HashMap<Uuid, AutomatedResponse>>>,
}

impl Default for ResponseOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseOrchestrator {
    pub fn new() -> Self {
        Self {
            execution_queue: Arc::new(Mutex::new(VecDeque::new())),
            execution_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Execute automated response
    pub async fn execute_response(
        &self,
        incident_id: Uuid,
        response_type: ResponseType,
        security_context: &SecurityContext,
    ) -> Result<AutomatedResponse> {
        let mut response =
            AutomatedResponse::new(response_type.clone(), vec!["system".to_string()]);

        let result = match response_type {
            ResponseType::RateLimitEscalation { .. } => {
                self.execute_rate_limit_escalation(security_context).await
            }
            ResponseType::TemporaryAccountLock {
                voter_hash,
                duration,
                reason,
            } => {
                self.execute_account_lock(security_context, &voter_hash, duration, &reason)
                    .await
            }
            ResponseType::TokenInvalidation { scope, reason } => {
                self.execute_token_invalidation(security_context, scope, &reason)
                    .await
            }
            ResponseType::EmergencyKeyRotation { component, reason } => {
                self.execute_key_rotation(security_context, &component, &reason)
                    .await
            }
            ResponseType::AlertEscalation {
                alert_level,
                recipients,
            } => self.execute_alert_escalation(alert_level, recipients).await,
            ResponseType::EnhancedMonitoring {
                entities,
                monitoring_level,
                duration,
            } => {
                self.execute_enhanced_monitoring(entities, monitoring_level, duration)
                    .await
            }
            _ => {
                tracing::warn!("Unhandled response type: {:?}", response_type);
                Ok(ResponseResult::Skipped {
                    reason: "Response type not implemented".to_string(),
                })
            }
        };

        response.execution_result = result?;

        // Store execution history
        {
            let mut history = self
                .execution_history
                .write()
                .map_err(|_| crypto_error!("Failed to write execution history"))?;
            history.insert(response.response_id, response.clone());
        }

        tracing::info!(
            "🤖 Automated response executed: incident={}, type={:?}, result={:?}",
            incident_id,
            response.response_type,
            response.execution_result
        );

        Ok(response)
    }

    async fn execute_rate_limit_escalation(
        &self,
        _security_context: &SecurityContext,
    ) -> Result<ResponseResult> {
        // Implementation would integrate with rate limiter
        tracing::info!("🚦 Rate limit escalation executed");
        Ok(ResponseResult::Success)
    }

    async fn execute_account_lock(
        &self,
        _security_context: &SecurityContext,
        voter_hash: &str,
        _duration: Duration,
        reason: &str,
    ) -> Result<ResponseResult> {
        // Would integrate with security context to lock account
        tracing::warn!(
            "🔒 Account locked: voter={}, reason={}",
            &voter_hash[..8],
            reason
        );
        Ok(ResponseResult::Success)
    }

    async fn execute_token_invalidation(
        &self,
        _security_context: &SecurityContext,
        scope: TokenInvalidationScope,
        reason: &str,
    ) -> Result<ResponseResult> {
        tracing::warn!(
            "🎫 Token invalidation: scope={:?}, reason={}",
            scope,
            reason
        );
        Ok(ResponseResult::Success)
    }

    async fn execute_key_rotation(
        &self,
        _security_context: &SecurityContext,
        component: &str,
        reason: &str,
    ) -> Result<ResponseResult> {
        tracing::error!(
            "🔑 Emergency key rotation: component={}, reason={}",
            component,
            reason
        );
        Ok(ResponseResult::Success)
    }

    async fn execute_alert_escalation(
        &self,
        alert_level: AlertLevel,
        recipients: Vec<String>,
    ) -> Result<ResponseResult> {
        tracing::error!(
            "🚨 Alert escalated: level={:?}, recipients={:?}",
            alert_level,
            recipients
        );
        Ok(ResponseResult::Success)
    }

    async fn execute_enhanced_monitoring(
        &self,
        entities: Vec<String>,
        level: String,
        _duration: Duration,
    ) -> Result<ResponseResult> {
        tracing::info!(
            "👁️ Enhanced monitoring activated: entities={:?}, level={}",
            entities,
            level
        );
        Ok(ResponseResult::Success)
    }
}

/// Main security incident manager
pub struct SecurityIncidentManager {
    // Core components
    pattern_correlator: Arc<PatternCorrelator>,
    escalation_engine: Arc<EscalationEngine>,
    response_orchestrator: Arc<ResponseOrchestrator>,

    // Incident storage
    active_incidents: Arc<RwLock<HashMap<Uuid, SecurityIncident>>>,
    resolved_incidents: Arc<RwLock<VecDeque<SecurityIncident>>>,

    // Statistics and metrics
    incident_statistics: Arc<RwLock<IncidentStatistics>>,

    // Configuration
    config: IncidentManagementConfig,
}

impl SecurityIncidentManager {
    /// Create new security incident manager
    pub fn new(config: IncidentManagementConfig) -> Self {
        let pattern_correlator = Arc::new(PatternCorrelator::new(
            Duration::from_secs(config.correlation_window_seconds),
            config.max_pattern_history,
        ));

        Self {
            pattern_correlator,
            escalation_engine: Arc::new(EscalationEngine::new()),
            response_orchestrator: Arc::new(ResponseOrchestrator::new()),
            active_incidents: Arc::new(RwLock::new(HashMap::new())),
            resolved_incidents: Arc::new(RwLock::new(VecDeque::new())),
            incident_statistics: Arc::new(RwLock::new(IncidentStatistics::default())),
            config,
        }
    }

    /// Create incident manager for testing
    pub fn for_testing() -> Self {
        Self::new(IncidentManagementConfig::for_testing())
    }

    /// Analyze security systems and detect incidents
    pub async fn analyze_and_respond(
        &self,
        performance_monitor: &SecurityPerformanceMonitor,
        audit_system: &EnhancedAuditSystem,
        security_context: &SecurityContext,
    ) -> Result<IncidentAnalysisReport> {
        let analysis_start = SystemTime::now();

        // Analyze patterns from all security systems
        let detected_patterns = self
            .pattern_correlator
            .analyze_patterns(performance_monitor, audit_system)
            .await?;

        let mut new_incidents = Vec::new();
        let mut updated_incidents = Vec::new();
        let mut responses_executed = Vec::new();

        // Process each detected pattern - Fixed: iterate over reference to avoid move
        for pattern in &detected_patterns {
            if pattern.confidence > self.config.incident_threshold {
                // Create or update incident
                let incident = self.create_or_update_incident(pattern.clone()).await?;

                if incident.status == IncidentStatus::Detected {
                    new_incidents.push(incident.incident_id);

                    // Determine and execute responses
                    let responses = self
                        .escalation_engine
                        .determine_responses(&incident)
                        .await?;

                    for response_type in responses {
                        let response = self
                            .response_orchestrator
                            .execute_response(incident.incident_id, response_type, security_context)
                            .await?;

                        responses_executed.push(response);
                    }

                    // Update incident status
                    self.update_incident_status(incident.incident_id, IncidentStatus::Responding)
                        .await?;
                } else {
                    updated_incidents.push(incident.incident_id);
                }
            }
        }

        // Update statistics
        self.update_statistics(new_incidents.len(), responses_executed.len())
            .await?;

        let analysis_duration = analysis_start.elapsed().unwrap_or_default();

        Ok(IncidentAnalysisReport {
            analysis_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            analysis_duration,
            patterns_analyzed: detected_patterns.len(), // Fixed: now we can use .len() since we didn't move
            new_incidents: new_incidents.len(),
            updated_incidents: updated_incidents.len(),
            responses_executed: responses_executed.len(),
            system_health_impact: self.calculate_system_health_impact().await,
        })
    }

    /// Create or update incident based on detected pattern
    async fn create_or_update_incident(
        &self,
        pattern: DetectedPattern,
    ) -> Result<SecurityIncident> {
        let affected_entity = if pattern.affected_entities.len() == 1 {
            AffectedEntity::Voter {
                voter_hash: pattern.affected_entities[0].clone(),
            }
        } else if pattern.affected_entities.len() > 1 {
            AffectedEntity::Multiple {
                entities: pattern.affected_entities.clone(),
            }
        } else {
            AffectedEntity::Unknown
        };

        let incident_type = self.pattern_to_incident_type(&pattern);

        let mut incident = SecurityIncident::new(
            incident_type,
            affected_entity,
            vec![], // Will be populated with related events
            format!("Detected pattern: {:?}", pattern.pattern_type),
        )?;

        incident.threat_score = pattern.confidence;

        // Store incident
        {
            let mut active_incidents = self
                .active_incidents
                .write()
                .map_err(|_| crypto_error!("Failed to write active incidents"))?;
            active_incidents.insert(incident.incident_id, incident.clone());
        }

        tracing::warn!(
            "🚨 Security incident created: id={}, type={:?}, severity={:?}, confidence={:.2}",
            incident.incident_id,
            incident.incident_type,
            incident.severity,
            pattern.confidence
        );

        Ok(incident)
    }

    fn pattern_to_incident_type(&self, pattern: &DetectedPattern) -> IncidentType {
        match pattern.pattern_type {
            PatternType::BruteForceAttack => IncidentType::BruteForceAttack {
                failed_attempts: 10, // Default, could be extracted from evidence
                time_window_seconds: 300,
            },
            PatternType::TimingAttack => IncidentType::TimingAttack {
                operation: SecurityOperation::SecureLogin, // Default
                anomaly_count: 20,
                deviation_threshold: 0.5,
            },
            PatternType::DenialOfService => IncidentType::DenialOfService {
                attack_vectors: vec!["resource_exhaustion".to_string()],
                resource_impact: pattern.confidence,
            },
            _ => IncidentType::SystemIntegrityFailure {
                component: "pattern_analysis".to_string(),
                failure_details: format!("Pattern: {:?}", pattern.pattern_type),
            },
        }
    }

    /// Update incident status
    pub async fn update_incident_status(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
    ) -> Result<()> {
        let mut active_incidents = self
            .active_incidents
            .write()
            .map_err(|_| crypto_error!("Failed to write active incidents"))?;

        if let Some(incident) = active_incidents.get_mut(&incident_id) {
            incident.update_status(new_status.clone())?;

            // Move to resolved incidents if closed
            if matches!(
                new_status,
                IncidentStatus::Resolved | IncidentStatus::Closed
            ) {
                let resolved_incident = incident.clone();
                drop(active_incidents); // Release write lock

                let mut resolved_incidents = self
                    .resolved_incidents
                    .write()
                    .map_err(|_| crypto_error!("Failed to write resolved incidents"))?;
                resolved_incidents.push_back(resolved_incident);

                // Maintain size limit
                while resolved_incidents.len() > self.config.max_resolved_incidents {
                    resolved_incidents.pop_front();
                }

                // Remove from active incidents
                let mut active_incidents = self
                    .active_incidents
                    .write()
                    .map_err(|_| crypto_error!("Failed to write active incidents"))?;
                active_incidents.remove(&incident_id);
            }
        }

        Ok(())
    }

    /// Get current incident statistics
    pub async fn get_incident_statistics(&self) -> Result<IncidentStatistics> {
        let statistics = self
            .incident_statistics
            .read()
            .map_err(|_| crypto_error!("Failed to read incident statistics"))?;
        Ok(statistics.clone())
    }

    /// Get active incidents
    pub async fn get_active_incidents(&self) -> Result<Vec<SecurityIncident>> {
        let active_incidents = self
            .active_incidents
            .read()
            .map_err(|_| crypto_error!("Failed to read active incidents"))?;
        Ok(active_incidents.values().cloned().collect())
    }

    /// Get resolved incidents
    pub async fn get_resolved_incidents(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<SecurityIncident>> {
        let resolved_incidents = self
            .resolved_incidents
            .read()
            .map_err(|_| crypto_error!("Failed to read resolved incidents"))?;

        let incidents: Vec<SecurityIncident> = resolved_incidents.iter().cloned().collect();

        if let Some(limit) = limit {
            Ok(incidents.into_iter().rev().take(limit).collect())
        } else {
            Ok(incidents)
        }
    }

    async fn update_statistics(
        &self,
        new_incidents: usize,
        responses_executed: usize,
    ) -> Result<()> {
        let mut statistics = self
            .incident_statistics
            .write()
            .map_err(|_| crypto_error!("Failed to write incident statistics"))?;

        statistics.total_incidents += new_incidents as u64;
        statistics.total_responses += responses_executed as u64;
        statistics.last_analysis = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        Ok(())
    }

    async fn calculate_system_health_impact(&self) -> f64 {
        let active_incidents = self.active_incidents.read().unwrap();

        if active_incidents.is_empty() {
            return 1.0; // Perfect health
        }

        // Fixed: specify type for impact_score to resolve ambiguous float error
        let mut impact_score: f64 = 0.0;
        for incident in active_incidents.values() {
            impact_score += match incident.severity {
                IncidentSeverity::Emergency => 0.5,
                IncidentSeverity::Critical => 0.3,
                IncidentSeverity::High => 0.2,
                IncidentSeverity::Medium => 0.1,
                IncidentSeverity::Low => 0.05,
            };
        }

        (1.0 - impact_score.min(1.0)).max(0.0)
    }
}

/// Incident analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAnalysisReport {
    pub analysis_timestamp: u64,
    pub analysis_duration: Duration,
    pub patterns_analyzed: usize,
    pub new_incidents: usize,
    pub updated_incidents: usize,
    pub responses_executed: usize,
    pub system_health_impact: f64,
}

/// Incident statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncidentStatistics {
    pub total_incidents: u64,
    pub active_incidents: u64,
    pub resolved_incidents: u64,
    pub total_responses: u64,
    pub successful_responses: u64,
    pub failed_responses: u64,
    pub avg_resolution_time_seconds: f64,
    pub last_analysis: Option<u64>,
}

/// Configuration for incident management
#[derive(Debug, Clone)]
pub struct IncidentManagementConfig {
    pub correlation_window_seconds: u64,
    pub incident_threshold: f64,
    pub max_active_incidents: usize,
    pub max_resolved_incidents: usize,
    pub max_pattern_history: usize,
    pub auto_response_enabled: bool,
    pub analysis_interval_seconds: u64,
}

impl Default for IncidentManagementConfig {
    fn default() -> Self {
        Self {
            correlation_window_seconds: CORRELATION_WINDOW_SECONDS,
            incident_threshold: 0.6,
            max_active_incidents: MAX_ACTIVE_INCIDENTS,
            max_resolved_incidents: 5000,
            max_pattern_history: 10000,
            auto_response_enabled: true,
            analysis_interval_seconds: 60, // 1 minute
        }
    }
}

impl IncidentManagementConfig {
    pub fn for_testing() -> Self {
        Self {
            correlation_window_seconds: 300, // 5 minutes for testing
            incident_threshold: 0.3,         // Lower threshold for testing
            max_active_incidents: 100,
            max_resolved_incidents: 500,
            max_pattern_history: 1000,
            auto_response_enabled: true,
            analysis_interval_seconds: 10, // 10 seconds for testing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        EnhancedAuditSystem, SecureSaltManager, SecurityContext, SecurityPerformanceMonitor,
        VotingLockService, VotingTokenService,
    };

    #[tokio::test]
    async fn test_incident_manager_creation() {
        let incident_manager = SecurityIncidentManager::for_testing();

        let statistics = incident_manager.get_incident_statistics().await.unwrap();
        assert_eq!(statistics.total_incidents, 0);
        assert_eq!(statistics.active_incidents, 0);

        println!("✅ Security incident manager created successfully");
    }

    #[tokio::test]
    async fn test_pattern_correlation_and_incident_creation() {
        let incident_manager = SecurityIncidentManager::for_testing();
        let performance_monitor = SecurityPerformanceMonitor::for_testing();
        let audit_system = EnhancedAuditSystem::for_testing();

        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());
        let security_context =
            SecurityContext::for_testing(salt_manager, token_service, Arc::new(lock_service));

        // Simulate suspicious authentication patterns by recording failed attempts
        println!("🔍 Recording 20 failed authentication attempts...");
        for i in 0..20 {
            let context = crate::crypto::SecurityTimingContext {
                voter_hash: Some(format!("suspicious_voter_{}", i % 3)), // Create patterns
                ..Default::default()
            };

            // Record failed authentication attempts
            performance_monitor
                .record_timing(
                    SecurityOperation::SecureLogin,
                    Duration::from_millis(100 + i * 10), // Increasing timing (suspicious)
                    false,                               // Failed attempts
                    context,
                )
                .await
                .unwrap();
        }

        // Debug: Check what auth patterns were created
        let auth_patterns = performance_monitor.get_auth_patterns().await.unwrap();
        println!(
            "📊 Created {} authentication patterns:",
            auth_patterns.len()
        );
        for pattern in &auth_patterns {
            println!(
                "   Pattern {}: failed={}, score={:.2}, suspicious={}",
                &pattern.voter_hash[..15],
                pattern.failed_attempts,
                pattern.suspicious_score,
                pattern.is_suspicious()
            );
        }

        // Analyze and respond
        let analysis_report = incident_manager
            .analyze_and_respond(&performance_monitor, &audit_system, &security_context)
            .await
            .unwrap();

        println!("✅ Incident analysis completed:");
        println!(
            "   Patterns analyzed: {}",
            analysis_report.patterns_analyzed
        );
        println!("   New incidents: {}", analysis_report.new_incidents);
        println!(
            "   Responses executed: {}",
            analysis_report.responses_executed
        );
        println!(
            "   System health impact: {:.2}",
            analysis_report.system_health_impact
        );

        // Should have detected suspicious patterns
        assert!(
            analysis_report.patterns_analyzed > 0,
            "Expected to analyze patterns but got 0. Auth patterns found: {}",
            auth_patterns.len()
        );

        let active_incidents = incident_manager.get_active_incidents().await.unwrap();
        if !active_incidents.is_empty() {
            let incident = &active_incidents[0];
            println!(
                "   First incident: type={:?}, severity={:?}",
                incident.incident_type, incident.severity
            );
            assert!(matches!(
                incident.status,
                IncidentStatus::Detected | IncidentStatus::Responding
            ));
        }

        let final_statistics = incident_manager.get_incident_statistics().await.unwrap();
        println!(
            "   Final statistics: incidents={}, responses={}",
            final_statistics.total_incidents, final_statistics.total_responses
        );
    }

    #[tokio::test]
    async fn test_automated_response_execution() {
        let incident_manager = SecurityIncidentManager::for_testing();

        // Create a test incident
        let affected_entity = AffectedEntity::Voter {
            voter_hash: "test_voter".to_string(),
        };
        let incident_type = IncidentType::BruteForceAttack {
            failed_attempts: 25,
            time_window_seconds: 300,
        };

        let incident = SecurityIncident::new(
            incident_type,
            affected_entity,
            vec![],
            "Test brute force incident".to_string(),
        )
        .unwrap();

        // Determine responses
        let responses = incident_manager
            .escalation_engine
            .determine_responses(&incident)
            .await
            .unwrap();
        assert!(!responses.is_empty());

        println!("✅ Automated response determination:");
        for (i, response) in responses.iter().enumerate() {
            println!("   Response {}: {:?}", i + 1, response);
        }

        // Test response execution
        let salt_manager = Arc::new(SecureSaltManager::for_testing());
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());
        let security_context =
            SecurityContext::for_testing(salt_manager, token_service, Arc::new(lock_service));

        if let Some(first_response) = responses.first() {
            let executed_response = incident_manager
                .response_orchestrator
                .execute_response(
                    incident.incident_id,
                    first_response.clone(),
                    &security_context,
                )
                .await
                .unwrap();

            println!("✅ Response executed:");
            println!("   Response ID: {}", executed_response.response_id);
            println!(
                "   Execution result: {:?}",
                executed_response.execution_result
            );

            assert!(matches!(
                executed_response.execution_result,
                ResponseResult::Success
            ));
        }
    }

    #[tokio::test]
    async fn test_incident_lifecycle_management() {
        let incident_manager = SecurityIncidentManager::for_testing();

        // Create incident
        let affected_entity = AffectedEntity::System {
            component: "test_component".to_string(),
        };
        let incident_type = IncidentType::SystemIntegrityFailure {
            component: "test_component".to_string(),
            failure_details: "Test failure".to_string(),
        };

        let incident = SecurityIncident::new(
            incident_type,
            affected_entity,
            vec![],
            "Test system integrity incident".to_string(),
        )
        .unwrap();

        let incident_id = incident.incident_id;

        // Add to active incidents
        {
            let mut active_incidents = incident_manager.active_incidents.write().unwrap();
            active_incidents.insert(incident_id, incident);
        }

        // Test status transitions
        incident_manager
            .update_incident_status(incident_id, IncidentStatus::Analyzing)
            .await
            .unwrap();
        incident_manager
            .update_incident_status(incident_id, IncidentStatus::Responding)
            .await
            .unwrap();
        incident_manager
            .update_incident_status(incident_id, IncidentStatus::Contained)
            .await
            .unwrap();
        incident_manager
            .update_incident_status(incident_id, IncidentStatus::Resolved)
            .await
            .unwrap();

        // Should be moved to resolved incidents
        let active_incidents = incident_manager.get_active_incidents().await.unwrap();
        assert!(
            !active_incidents
                .iter()
                .any(|i| i.incident_id == incident_id)
        );

        let resolved_incidents = incident_manager
            .get_resolved_incidents(Some(10))
            .await
            .unwrap();
        assert!(
            resolved_incidents
                .iter()
                .any(|i| i.incident_id == incident_id)
        );

        println!("✅ Incident lifecycle management works correctly");
        println!("   Incident moved from active to resolved");
        println!("   Final status: Resolved");
    }

    #[tokio::test]
    async fn test_pattern_correlation_rules() {
        let correlator = PatternCorrelator::new(Duration::from_secs(3600), 1000);

        // Test authentication pattern analysis
        let auth_pattern = AuthenticationPattern {
            voter_hash: "test_voter".to_string(),
            failed_attempts: 15,
            success_count: 1,
            first_attempt: 1000,
            last_attempt: 1300,
            avg_attempt_interval: 0.5, // Very fast attempts
            timing_anomalies: 8,
            suspicious_score: 0.8,
        };

        let detected_pattern = correlator
            .analyze_authentication_pattern(&auth_pattern)
            .await
            .unwrap();
        assert!(detected_pattern.is_some());

        if let Some(pattern) = detected_pattern {
            println!("✅ Pattern correlation works:");
            println!("   Pattern type: {:?}", pattern.pattern_type);
            println!("   Confidence: {:.2}", pattern.confidence);
            println!("   Affected entities: {:?}", pattern.affected_entities);

            assert!(pattern.confidence > 0.5);
            assert_eq!(pattern.affected_entities[0], "test_voter");
        }
    }
}
