//! Blueprint contract invariants (research doc §9.4) exercised end to end
//! against the real rule corpus:
//!
//! - I1 determinism, I2 one-way flow, I3 idempotence, I4 failure semantics.
//!
//! Fixture values are documented examples / obviously-fake strings.

use secret_guard_plugin::{Mode, Policy, SecretGuardTransform};
use serde_json::json;
use shannon_plugin_api::{
    ContextTransform, FailMode, IngestBlock, IngestSource, RestoreAction, TransformAction,
};

const KEY: &[u8] = b"blueprint-invariants-master-key-0123";

fn policy(mode: Mode, fail_mode: FailMode) -> Policy {
    Policy {
        fail_mode,
        mode,
        max_findings: 500,
    }
}

fn redact() -> SecretGuardTransform {
    SecretGuardTransform::with_embedded_rules(KEY.to_vec(), policy(Mode::Redact, FailMode::Open))
        .expect("valid config")
}

/// I1: the same content always transforms to the same bytes — across
/// instances with the same key (prompt-cache byte-stability).
#[test]
fn i1_determinism_across_instances_and_repeats() {
    let t1 = redact();
    let t2 = redact();
    let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";

    let mut b1 = IngestBlock {
        source: IngestSource::ToolResult {
            tool: "Read".to_string(),
        },
        text: content.to_string(),
    };
    let mut b2 = IngestBlock {
        source: IngestSource::ToolResult {
            tool: "Read".to_string(),
        },
        text: content.to_string(),
    };
    let a1 = t1.transform_ingest(&mut b1);
    let a2 = t2.transform_ingest(&mut b2);
    assert_eq!(a1, TransformAction::Modified);
    assert_eq!(a1, a2);
    assert_eq!(b1.text, b2.text);

    // Same instance, repeated content → same bytes again.
    let mut b3 = IngestBlock {
        source: IngestSource::UserMessage,
        text: content.to_string(),
    };
    let _ = t1.transform_ingest(&mut b3);
    assert_eq!(b3.text, b1.text);
}

/// I2: surrogates enter history; real values appear only on the execution
/// face (restored tool args) and never flow back into history text.
#[test]
fn i2_one_way_flow_history_stays_surrogate_only() {
    let t = redact();
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let mut block = IngestBlock {
        source: IngestSource::ToolResult {
            tool: "Read".to_string(),
        },
        text: format!("id={secret}"),
    };
    assert_eq!(t.transform_ingest(&mut block), TransformAction::Modified);

    // "History" now holds the surrogate…
    let history = block.text.clone();
    assert!(history.contains("SG1:"), "history: {history}");
    assert!(!history.contains(secret), "raw secret leaked into history");

    // …while the model's echo of the surrogate restores only in the tool
    // args handed to the executor.
    let surrogate = history.trim_start_matches("id=");
    let mut args = json!({ "file_path": "/app/.env", "content": format!("id={surrogate}") });
    let action = t.restore_tool_args("Write", &mut args);
    match action {
        RestoreAction::Restored(stats) => {
            assert_eq!(stats.replaced, 1);
            assert!(stats.unresolved.is_empty());
        }
        other => panic!("expected Restored, got {other:?}"),
    }
    assert_eq!(args["content"], format!("id={secret}"));
    // History string untouched by the restore.
    assert_eq!(history, block.text);
    assert!(!history.contains(secret));
}

/// I3: transforming already-transformed content is a no-op — otherwise each
/// turn rewrites the prefix and provider prompt caching collapses.
#[test]
fn i3_idempotence_second_pass_is_passthrough() {
    let t = redact();
    let mut block = IngestBlock {
        source: IngestSource::ToolResult {
            tool: "Read".to_string(),
        },
        text: "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".to_string(),
    };
    assert_eq!(t.transform_ingest(&mut block), TransformAction::Modified);
    let once = block.text.clone();

    let mut again = IngestBlock {
        source: IngestSource::ToolResult {
            tool: "Read".to_string(),
        },
        text: once.clone(),
    };
    assert_eq!(t.transform_ingest(&mut again), TransformAction::Passthrough);
    assert_eq!(
        again.text, once,
        "second pass must not change a single byte"
    );
}

/// I3-adjacent: audit over an already-redacted wire reports nothing once the
/// registry is in play is a host concern; the plugin's own audit (Phase 0,
/// no registry filter) still detects — documented distinction.
#[test]
fn audit_detects_on_raw_wire() {
    let t = redact();
    let wire = json!({
        "model": "claude-sonnet-4-5",
        "messages": [
            { "role": "user", "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" }
        ]
    });
    let findings = t.audit_wire(&wire);
    assert!(findings.iter().any(|f| f.rule_id == "aws-access-token"));
}

/// I4: fail modes decide, never silence. Construction failures are fail-fast;
/// runtime failures map through the declared FailMode.
#[test]
fn i4_failure_semantics_are_explicit() {
    // Fail-fast at construction.
    assert!(
        SecretGuardTransform::with_embedded_rules(b"tiny".to_vec(), Policy::default()).is_err()
    );

    // Runtime mapping: closed blocks with a reason, open passes through.
    let block = IngestBlock {
        source: IngestSource::Other,
        text: "x".to_string(),
    };
    let closed = secret_guard_plugin::failure_to_ingest_action(FailMode::Closed, "boom");
    assert_eq!(
        closed,
        TransformAction::Blocked {
            reason: "boom".to_string()
        }
    );
    assert_eq!(
        secret_guard_plugin::failure_to_ingest_action(FailMode::Open, "boom"),
        TransformAction::Passthrough
    );
    let _ = block; // block untouched by the failure path
}

/// Restore reports unresolved placeholder-looking tokens instead of silently
/// shipping them (blueprint F3/F4).
#[test]
fn restore_surfaces_unresolved_tokens() {
    let t = redact();
    let mut text = String::from("the model invented SG1:ZZZZZZZZZZZZZZZZ here");
    match t.restore_display(&mut text) {
        RestoreAction::Restored(stats) => {
            assert_eq!(stats.unresolved, ["SG1:ZZZZZZZZZZZZZZZZ"]);
        }
        other => panic!("expected Restored with unresolved, got {other:?}"),
    }
    assert!(
        text.contains("SG1:ZZZZZZZZZZZZZZZZ"),
        "unknown token must not be swallowed"
    );
}

/// Restore is a no-op on clean text and an Unchanged on an empty registry.
#[test]
fn restore_unchanged_without_registry_hits() {
    let t = redact();
    let mut text = String::from("no placeholders here");
    assert_eq!(t.restore_display(&mut text), RestoreAction::Unchanged);
    assert_eq!(text, "no placeholders here");
}
