# Rust — Verification Stack Implementation (R0 → R8)

Concrete `Cargo.toml` lint tables, idiomatic algebraic state machines, and runnable Rust (edition 2024) reference crate implementing the universal principles from [../SKILL.md](../SKILL.md) in Rust.

- **Runnable R0–R5 Reference Crate:** `templates/rust-reference/` (`order-lifecycle-ref`: pure `enum` state machine, JSON Tests-as-Data table, `proptest` PBT + Stateful MBT, `mutants.toml`).
- **Cross-Language `vstack` CLI Support:** `vstack scan`, `vstack state-machines`, `vstack no-comments`, `vstack diff-cheats`, and `vstack classify` natively analyze `.rs`, `Cargo.toml`, `rustfmt.toml`, and `mutants.toml`.

---

## 1. Universal Rule → Rust Implementation Matrix

| Universal Rule | Rung | Native `rustc` / `clippy` / `cargo` Enforcement | `vstack` Scanner Coverage |
| :--- | :---: | :--- | :--- |
| **`no-comments`** | R0 | `vstack no-comments . --fail` (allows `pub ///`, `//!`, `// SAFETY:`, `// WARNING:`, SPDX; bans prose and private `///`) | `src/no-comments.ts` |
| **`no-implicit-state-machine`** | R0/R1 | `rustc` exhaustive `match` + `clippy::wildcard_enum_match_arm = "deny"` | `vstack state-machines . --fail` (`src/state-machines/rust.ts`: boolean soup, `Option<T>` state-bag, scattered `.status`/`.state` mutations, silent `_ =>` wildcard arms) |
| **`no-unsafe-escape-hatch`** | R0/R1 | `[lints.rust] unsafe_code = "forbid"`, `[lints.clippy] unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"` | `no-chained-or-any-cast` (`unsafe`/`transmute` without `// SAFETY:`, prod `.unwrap()`/`.expect(`) |
| **`no-swallowing-catch` & `suppression-audit`** | R0 | `[lints.rust] warnings = "deny"`, `clippy::allow_attributes_without_reason = "deny"` | `no-swallowing-catch` (`Err(_) => {}`), `suppression-audit` (`#[allow(clippy::...|warnings|dead_code|unused)]` without `reason =`), `diff-rust-allow-lint` |
| **`no-test-only-production-seam`** | R0/R1 | Module privacy (`pub(crate)` / private modules) | `no-test-only-production-seam` (`_for_testing`, `_test_only`, `for_testing`) |
| **`test-integrity` (Landmines)** | R0 | `cargo clippy --all-targets -- -D warnings` + `vstack scan` | `no-fixed-sleep` (`thread::sleep`/`tokio::time::sleep`), `test-discipline` (`#[ignore]`), `weak-asserts-tautology` (`assert!(true)`/`assert_eq!(1, 1)`), `self-derived-expectation` (`assert_eq!(f(x), f(x))`), `no-elapsed-time-bound` (`.elapsed() <`), `no-imported-mutation` (`env::set_var`), `no-test-nondeterminism` (`SystemTime::now`/`rand::*`), `no-multi-status-assertion` (`[200, 404].contains(`), `no-unexercised-test` |
| **Formatting & Architecture** | R1 | `cargo fmt --check`, workspace crate DAG boundaries (`Cargo.toml`), `cargo-udeps` / `cargo-deny` | `structure.ts` + `ci-auditor.ts` |

---

## 2. Drop-In `Cargo.toml` Static Guardrails

Add strict compiler and Clippy lint tables directly in `Cargo.toml` (Rust 1.74+ / edition 2024):

```toml
[lints.rust]
unsafe_code = "forbid"
warnings = "deny"

[lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
wildcard_enum_match_arm = "deny"
```

### Explicit State Machine Idiom (Rust)

Rust's algebraic `enum` + `#[must_use]` + `wildcard_enum_match_arm = "deny"` makes illegal states and unhandled variants compile-time errors:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderState {
    Pending { amount_cents: u32 },
    Authorized { amount_cents: u32, auth_code: String },
    Shipped { amount_cents: u32, auth_code: String, tracking_id: String },
    Cancelled { reason: String },
}

#[must_use]
pub fn transition(state: OrderState, event: OrderEvent) -> TransitionOutcome {
    match state {
        OrderState::Pending { amount_cents } => { /* ... */ }
        OrderState::Authorized { amount_cents, auth_code } => { /* ... */ }
        OrderState::Shipped { .. } => { /* ... */ }
        OrderState::Cancelled { .. } => { /* ... */ }
    }
}
```

Note on Rust tests: return `Result<(), String>` and use `assert_eq!` in integration tests so `clippy::panic = "deny"` stays enforced across **all targets** (`cargo clippy --all-targets -- -D warnings`) with zero `#[allow(...)]` suppressions!

---

## 3. R0–R8 Tooling & Reference Proof (`templates/rust-reference/`)

| Rung | Mechanism | Proof / Recommended Rust Tools | Command |
| :---: | :--- | :--- | :--- |
| **R0** | Strict formatting, `rustc`/`clippy`, `no-comments`, anti-cheat | `Cargo.toml` `[lints.*]`, `rustfmt.toml` | `cargo fmt --check && cargo clippy --all-targets -- -D warnings` |
| **R1** | Closed `enum` state machine + crate DAG boundaries | `src/lib.rs` (`OrderState`, `transition`) | `vstack state-machines templates/rust-reference --fail` |
| **R2** | Tests-as-Data JSON table + PBT | `tests/fixtures/transitions.json`, `tests/transition_table.rs`, `proptest!` | `cargo test` |
| **R3** | Stateful MBT, In-Process Host, Contracts & Twins | `tests/property_and_mbt.rs` / `proptest-state-machine`, `tower::ServiceExt::oneshot`, `actix_web::test`, `wiremock` | `cargo test` |
| **R4** | Real DB, Migrations, Bus DLQ & DST | `sqlx::test` + real migrations, `testcontainers`, **`turmoil`** (deterministic network simulation) | `cargo test --test integration` |
| **R5** | Formal Verification, Mutation, Fuzzing & System 1 Circuits | **`stateright`** (`tests/formal_model_check.rs`, exhaustive BFS), **`kani`** (`#[cfg(kani)]` harnesses in `src/lib.rs`), **`loom`** / **`verus`**, **`cargo-mutants`** (`mutants.toml`), `cargo-fuzz`, `vstack circuit` / `vstack classify` | `cargo test && cargo mutants` |
| **R6** | Benchmarks & Load | `criterion` / `divan`, `k6` | `cargo bench` |
| **R7** | Thin Golden-Path E2E (5–15 journeys max) | Real compiled binary + real external edges | E2E harness |
| **R8** | Production Verification | `tracing` + OpenTelemetry, canary rollouts, synthetics | Continuous |
