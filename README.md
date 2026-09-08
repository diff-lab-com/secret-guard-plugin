# secret-guard-plugin

Blueprint artifact **(b)**: the secret-guard plugin implementing
[`shannon_plugin_api::ContextTransform`] — the Shannon content-transform
contract (artifact **c**, a member crate of `shannon-mono`) — over the pure
`secret-guard` primitives (artifact **a**, separate repo).

```
a: secret-guard (pure lib)  ←──  b: this crate  ──>  c: shannon-plugin-api (contract)
                                          ↑
                                 shannon-mono engine wiring
```

## Why in-process

The contract is the plugin boundary, **not** a process boundary. Secret
protection sits on the content/request hot path; IPC there would add a
partial-failure class (crashed plugin = fail-open leak or fail-closed
blocked work) and per-block latency. Out-of-process plugin forms are a later
evolution of the same contract, not the v1 (blueprint §9.1 constraint 1).

## What it implements

| Contract wiring point | Behavior |
|---|---|
| `transform_ingest` | `Mode::AuditOnly` (default): never modifies. `Mode::Redact`: replaces findings with deterministic `SG1:` surrogates and registers the pair. |
| `restore_tool_args` | walks the JSON args recursively; restores real values for registered surrogates (exact + fuzzy case repair); reports unresolved tokens. |
| `restore_display` | same for display/IM text. |
| `audit_wire` | read-only scan of the serialized request; findings carry rule ids only — no secret material crosses the contract. |

Blueprint invariants are exercised in `tests/blueprint_invariants.rs`:
I1 determinism (cache-safe bytes), I2 one-way flow (history stays
surrogate-only), I3 idempotence (second pass is a byte-identical no-op),
I4 explicit failure semantics (`FailMode::Closed` → `Blocked`/`Failed`,
`Open` → passthrough; construction errors fail fast).

## Host composition example

```rust
use std::sync::Arc;
use secret_guard_plugin::{Mode, Policy, SecretGuardTransform};
use shannon_plugin_api::FailMode;

let policy = Policy { fail_mode: FailMode::Open, mode: Mode::Redact, max_findings: 500 };
let plugin = SecretGuardTransform::with_embedded_rules(master_key, policy)?;
shannon::secret_guard::set_context_transform(Some(Arc::new(plugin)));
// Phase 0 already audits every outbound request through this seam;
// ingest/restore wiring points light up as the engine adopts them.
```

## Registry scope (pilot)

The surrogate→secret registry currently lives inside the transform
(`RwLock<BTreeMap>`). The derivation is stateless HMAC — the registry is a
rebuildable cache, never the source of truth. Production intent is
host-owned state (persisted next to the session, reconstructible from local
secret sources); migrating it out does not change the contract.

## Dependencies during development

Both dependencies are sibling path checkouts (three artifacts, three
separate git repos):

```toml
secret-guard       = { path = "../secret-guard" }
shannon-plugin-api = { path = "../shannon-plugin-api/crates/shannon-plugin-api" }
```

On publish, switch to git / crates.io deps (see `Cargo.toml` comments).

## License

MIT.
