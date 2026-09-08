//! # secret-guard-plugin
//!
//! Blueprint artifact **(b)**: an implementation of
//! [`shannon_plugin_api::ContextTransform`] (the Shannon content-transform
//! contract) over the pure `secret-guard` primitives.
//!
//! In-process by design: the contract is the plugin boundary, not a process
//! boundary — secret-protection runs on the request/content hot path and
//! must not pay IPC costs or add a partial-failure class there (blueprint
//! §9.1 constraint 1).
//!
//! Registry scope (pilot): the surrogate→secret registry lives inside the
//! transform behind an `RwLock`. Production intent (blueprint §9.2/§9.3) is
//! host-owned state — the derivation is stateless HMAC, so the registry is
//! a rebuildable cache and can migrate to the host without contract change.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::RwLock;

use secret_guard::engine::{scan, substitute, ScanConfig};
use secret_guard::restore::{restore, RestoreOutcome};
use secret_guard::rules::RuleSet;
use secret_guard::surrogate::{surrogate as derive_surrogate, SecretShape};
use shannon_plugin_api::{
    AuditFinding, ContextTransform, FailMode, IngestBlock, RestoreAction, RestoreStats,
    TransformAction,
};

/// What to do with detected secrets at the ingest wiring point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Detect and count only; content is never modified (Phase 0/1 posture).
    #[default]
    AuditOnly,
    /// Replace detected secrets with deterministic surrogates (Phase 2).
    Redact,
}

/// Plugin policy, supplied by the host composition.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Behavior on internal plugin failure (blueprint I4).
    pub fail_mode: FailMode,
    /// Audit-only vs. redact-at-ingest.
    pub mode: Mode,
    /// Per-scan findings cap (safety valve).
    pub max_findings: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_mode: FailMode::Open,
            mode: Mode::AuditOnly,
            max_findings: 500,
        }
    }
}

/// Configuration error at construction time (fail fast — blueprint I4's
/// cleanest form: a plugin that cannot be configured never installs).
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret-guard-plugin config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Map an internal failure to an ingest action per the declared fail mode.
pub fn failure_to_ingest_action(fail_mode: FailMode, reason: impl Into<String>) -> TransformAction {
    match fail_mode {
        FailMode::Closed => TransformAction::Blocked {
            reason: reason.into(),
        },
        FailMode::Open => TransformAction::Passthrough,
    }
}

/// Map an internal failure to a restore action per the declared fail mode.
pub fn failure_to_restore_action(fail_mode: FailMode, reason: impl Into<String>) -> RestoreAction {
    match fail_mode {
        FailMode::Closed => RestoreAction::Failed {
            reason: reason.into(),
        },
        FailMode::Open => RestoreAction::Unchanged,
    }
}

/// The secret-guard `ContextTransform`.
#[derive(Debug)]
pub struct SecretGuardTransform {
    master_key: Vec<u8>,
    rules: RuleSet,
    policy: Policy,
    /// Surrogate → real value. Rebuildable cache (HMAC derivation is
    /// stateless); pilot keeps it in-process.
    registry: RwLock<BTreeMap<String, String>>,
}

impl SecretGuardTransform {
    /// Build a transform. `master_key` must be ≥16 bytes of entropy.
    ///
    /// # Errors
    /// [`ConfigError`] on a too-short master key or an unusable rule set.
    pub fn new(master_key: Vec<u8>, rules: RuleSet, policy: Policy) -> Result<Self, ConfigError> {
        if master_key.len() < 16 {
            return Err(ConfigError(
                "master key must be at least 16 bytes".to_string(),
            ));
        }
        if rules.is_empty() {
            return Err(ConfigError("rule set is empty".to_string()));
        }
        Ok(Self {
            master_key,
            rules,
            policy,
            registry: RwLock::new(BTreeMap::new()),
        })
    }

    /// Build with the embedded starter ruleset.
    ///
    /// # Errors
    /// Same as [`Self::new`], plus embedded-ruleset load failure.
    pub fn with_embedded_rules(master_key: Vec<u8>, policy: Policy) -> Result<Self, ConfigError> {
        let rules =
            RuleSet::embedded().map_err(|e| ConfigError(format!("embedded ruleset: {e}")))?;
        Self::new(master_key, rules, policy)
    }

    /// Shape used for surrogate derivation. Generic `SG1:` tokens are
    /// self-describing (fuzzy-repairable); swap in format-preserving shapes
    /// per secret class when the host policy grows per-class rules.
    fn shape() -> SecretShape {
        SecretShape::Generic
    }

    fn scan_config(&self, protected: Vec<String>) -> ScanConfig {
        ScanConfig {
            rules: self.rules.clone(),
            protected_values: protected,
            max_findings: self.policy.max_findings,
        }
    }

    /// Current registry as (surrogate, real) pairs.
    ///
    /// `Err(())` signals a poisoned lock — the I4 failure path.
    fn pairs_snapshot(&self) -> Result<Vec<(String, String)>, ()> {
        self.registry
            .read()
            .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .map_err(|_| ())
    }

    fn register(&self, surrogate: String, secret: String) -> Result<(), ()> {
        self.registry
            .write()
            .map(|mut g| {
                g.insert(surrogate, secret);
            })
            .map_err(|_| ())
    }

    /// Restored values live on the execution/display face only — the caller
    /// decides where they land; they never re-enter conversation history.
    fn restore_string(&self, text: &mut String) -> RestoreAction {
        let pairs = match self.pairs_snapshot() {
            Ok(p) => p,
            Err(_) => {
                return failure_to_restore_action(
                    self.policy.fail_mode,
                    "secret-guard registry lock poisoned",
                )
            }
        };
        let refs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let RestoreOutcome {
            text: restored,
            replaced,
            fuzzy,
            unresolved,
        } = restore(text, &refs);
        if replaced == 0 && fuzzy == 0 && unresolved.is_empty() {
            RestoreAction::Unchanged
        } else {
            *text = restored;
            RestoreAction::Restored(RestoreStats {
                replaced,
                fuzzy,
                unresolved,
            })
        }
    }
}

fn restore_value(v: &mut serde_json::Value, pairs: &[(&str, &str)], stats: &mut RestoreStats) {
    match v {
        serde_json::Value::String(s) => {
            let out = restore(s, pairs);
            stats.replaced += out.replaced;
            stats.fuzzy += out.fuzzy;
            stats.unresolved.extend(out.unresolved);
            *s = out.text;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                restore_value(item, pairs, stats);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, item) in map {
                restore_value(item, pairs, stats);
            }
        }
        _ => {}
    }
}

impl ContextTransform for SecretGuardTransform {
    fn transform_ingest(&self, block: &mut IngestBlock) -> TransformAction {
        if self.policy.mode == Mode::AuditOnly {
            // Phase 0/1: never modify at ingest. (Detection telemetry flows
            // through `audit_wire`; blocking policies live in Phase 1.)
            return TransformAction::Passthrough;
        }
        let protected = match self.pairs_snapshot() {
            Ok(pairs) => pairs.into_iter().map(|(k, _)| k).collect(),
            Err(_) => {
                return failure_to_ingest_action(
                    self.policy.fail_mode,
                    "secret-guard registry lock poisoned",
                )
            }
        };
        let findings = scan(&block.text, &self.scan_config(protected));
        if findings.is_empty() {
            return TransformAction::Passthrough;
        }
        let surrogate_of =
            |secret: &str| derive_surrogate(secret, &self.master_key, &Self::shape());
        // Register before substitution so the wire built from this block can
        // be restored even if the process dies before the next turn.
        let mut first_error: Option<String> = None;
        for f in &findings {
            let token = surrogate_of(&f.secret);
            if let Err(()) = self.register(token, f.secret.clone()) {
                first_error
                    .get_or_insert_with(|| "secret-guard registry lock poisoned".to_string());
            }
        }
        if let Some(reason) = first_error {
            return failure_to_ingest_action(self.policy.fail_mode, reason);
        }
        let out = substitute(&block.text.clone(), &findings, |f| {
            Some(surrogate_of(&f.secret))
        });
        block.text = out;
        TransformAction::Modified
    }

    fn restore_tool_args(&self, _tool: &str, args: &mut serde_json::Value) -> RestoreAction {
        let pairs = match self.pairs_snapshot() {
            Ok(pairs) => pairs,
            Err(_) => {
                return failure_to_restore_action(
                    self.policy.fail_mode,
                    "secret-guard registry lock poisoned",
                )
            }
        };
        let refs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let mut stats = RestoreStats {
            replaced: 0,
            fuzzy: 0,
            unresolved: Vec::new(),
        };
        restore_value(args, &refs, &mut stats);
        stats.unresolved.sort();
        stats.unresolved.dedup();
        if stats.replaced == 0 && stats.fuzzy == 0 && stats.unresolved.is_empty() {
            RestoreAction::Unchanged
        } else {
            RestoreAction::Restored(stats)
        }
    }

    fn restore_display(&self, text: &mut String) -> RestoreAction {
        self.restore_string(text)
    }

    fn audit_wire(&self, wire: &serde_json::Value) -> Vec<AuditFinding> {
        let body = serde_json::to_string(wire).unwrap_or_default();
        if body.is_empty() {
            return Vec::new();
        }
        scan(&body, &self.scan_config(Vec::new()))
            .into_iter()
            .map(|f| AuditFinding { rule_id: f.rule_id })
            .collect()
    }
}

impl SecretGuardTransform {
    /// Surrogate for a secret under this instance's key (test/diagnostic
    /// aid; production hosts derive via the registry).
    pub fn surrogate_for(&self, secret: &str) -> String {
        derive_surrogate(secret, &self.master_key, &Self::shape())
    }

    /// Number of registered surrogates.
    pub fn registry_len(&self) -> usize {
        self.registry.read().map(|g| g.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shannon_plugin_api::IngestSource;

    const KEY: &[u8] = b"plugin-test-master-key-0123456789";

    fn redact_transform() -> SecretGuardTransform {
        let policy = Policy {
            mode: Mode::Redact,
            ..Policy::default()
        };
        SecretGuardTransform::with_embedded_rules(KEY.to_vec(), policy).expect("valid config")
    }

    #[test]
    fn short_master_key_fails_fast() {
        let err = SecretGuardTransform::with_embedded_rules(b"short".to_vec(), Policy::default())
            .expect_err("must reject");
        assert!(err.0.contains("16 bytes"));
    }

    #[test]
    fn audit_only_mode_never_modifies() {
        let t = SecretGuardTransform::with_embedded_rules(KEY.to_vec(), Policy::default())
            .expect("valid config");
        let mut block = IngestBlock {
            source: IngestSource::ToolResult {
                tool: "Read".to_string(),
            },
            text: "AKIAIOSFODNN7EXAMPLE".to_string(),
        };
        assert_eq!(t.transform_ingest(&mut block), TransformAction::Passthrough);
        assert_eq!(block.text, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn audit_wire_reports_rules_without_secrets() {
        let t = redact_transform();
        let wire = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "messages": [{ "role": "user", "content": "id = AKIAIOSFODNN7EXAMPLE" }]
        });
        let findings = t.audit_wire(&wire);
        assert!(findings.iter().any(|f| f.rule_id == "aws-access-token"));
        // AuditFinding has no field that could carry the secret — enforced
        // by the type itself; this assert documents the intent.
        for f in &findings {
            assert!(f.rule_id.len() < 64);
        }
    }

    #[test]
    fn failure_mapping_respects_fail_mode() {
        let closed = failure_to_ingest_action(FailMode::Closed, "boom");
        assert_eq!(
            closed,
            TransformAction::Blocked {
                reason: "boom".to_string()
            }
        );
        let open = failure_to_ingest_action(FailMode::Open, "boom");
        assert_eq!(open, TransformAction::Passthrough);
        let closed = failure_to_restore_action(FailMode::Closed, "boom");
        assert!(matches!(closed, RestoreAction::Failed { .. }));
        assert_eq!(
            failure_to_restore_action(FailMode::Open, "boom"),
            RestoreAction::Unchanged
        );
    }
}
