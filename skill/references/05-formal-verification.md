# 05 — Universal Formal Verification Guide (`R5 / V25`)

Formal verification proves safety and reachability invariants across **every reachable state or input** — not just the samples a unit test or PBT happened to hit.

---

## 1. When to Use Formal Verification vs PBT / MBT

| Problem Shape | Best Mechanism | Why |
| :--- | :--- | :--- |
| Pure math / parser / validation matrix | **R2 Tests-as-Data + PBT** | Fast, zero model-maintenance overhead |
| Stateful aggregate with modest transitions | **R3 Stateful MBT** → **R5 Exhaustive Model Check** | MBT shrinks counterexamples; exhaustive model check proves **0 unreachable/illegal states** |
| Concurrency, distributed consensus, billing/ledger, locks, circuit breakers | **R5 Formal Spec (`Quint`/`TLA+`) + Code-Level Model Check / SMT (`Stateright`/`Kani`/`Z3`/`Dafny`/`Loom`)** | Random sampling misses rare 1-in-10^6 interleavings and arithmetic edge cases |

**Rule of Thumb:** Write **1 formal spec or exhaustive model check** per critical state machine, protocol, ledger, or safety governor. Never formally verify CRUD glue or UI layout.

---

## 2. The 4 Universal Formal Verification Tiers

1. **Protocol / State-Machine Model Checking (`Quint` / `TLA+` / `everystate` / `Stateright`):**
   - Models states, allowed transitions, `always` safety invariants (e.g., *"shipped order was always authorized first"*, *"terminal state never mutates"*), and `sometimes` reachability witnesses (proves invariants aren't vacuously true because the state is unreachable!).
   - Canonical universal spec in this repo: [templates/formal/order_lifecycle.qnt](../../templates/formal/order_lifecycle.qnt).
2. **SMT Algebraic & Boundary Proofs (`Z3`):**
   - Proves arithmetic bounds, discount/pricing monotonicity, permission lattices, and integer overflow absence over **all** integers/bitvectors simultaneously.
3. **Bounded Code-Level Proofs & Verified Contracts (`Kani` for Rust, `Dafny` for C#/.NET, `Verus`):**
   - Verifies actual implementation functions directly (no spec↔code drift) for panic freedom, arithmetic bounds, and postconditions.
4. **Concurrency Schedule Exploration (`Loom` / `Shuttle`):**
   - Exhaustively explores thread/async interleavings to catch data races, deadlocks, and lost wakeups deterministically.
5. **Sub-Second Constructive Laws (`Bend 2` / `LAWS.bend` + `vstack laws`):**
   - Declares human-owned algebraic laws (`law cancel_idempotent(o: Order): {cancel(cancel(o)) == cancel(o) : Order}`) locked in `CODEOWNERS` so agents cannot weaken invariants, paired with explicit constructive proofs (`def cancel_idempotent`) verified sub-second via `bend check LAWS.bend --safe`.
   - Reference template: [templates/bend2-reference/LAWS.bend](../../templates/bend2-reference/LAWS.bend). Audit ownership, proof witnesses, and escape hatches (`sorry`/`admit`/`unsafe`) via `vstack laws . --verify --fail`.

---

## 3. Preventing Spec ↔ Code Drift

A formal spec that drifts from production code is worse than no spec because it keeps passing on code that no longer exists. Pair every formal model with:
- **Sync-Commit Drift Gate (`vstack formal-sync`):** Record `{ id, specFile, coveredPaths, syncCommit }` under `formalChecks[]` in `.verification/control-plan.json`. `vstack scan` and `vstack formal-sync --fail` fail automatically whenever covered production files change after `syncCommit` until you re-audit the spec, prove a scratch break still fails, and advance `syncCommit`.
- **Direct Code Verification:** Run the model checker directly against production functions (as in `templates/rust-reference/tests/formal_model_check.rs`, `templates/csharp-reference/OrderLifecycle.Tests/OrderFormalProofTests.cs`, `templates/python-reference/tests/test_formal_model_check.py`, and `tests/formal-verification.test.ts`).
- **Practical Adoption Ramp (Quint → TLC → ITF Traces → MBT → Prover):** Start by modeling one real aggregate in Quint/TLA+, exhaustively check transitions with TLC, replay emitted ITF traces directly against production code as R3 Model-Based Tests, add R2 PBTs, and reach for full theorem provers (Dafny/Verus/Lean) only for unbounded proofs. Generate user-facing statecharts directly from the checked model so diagrams cannot drift.
- **Reachability Witnesses (`sometimes`):** Pair every safety invariant with at least one reachability witness proving the guarded states are reachable.

---

## 4. Per-Language Runnable Proofs in This Repo

| Language | Universal / Native Tools | Runnable Proof in This Repo |
| :--- | :--- | :--- |
| **Universal (Protocol)** | **Quint** (`.qnt`), **TLA+** (`.tla` / `everystate`), **Alloy** (`.als`), **Bend 2** (`LAWS.bend`) | `templates/formal/order_lifecycle.qnt`, `templates/bend2-reference/LAWS.bend` |
| **TypeScript / JS** | Exhaustive state-space model check, `z3-solver` (WASM SMT), Quint trace replay | `tests/formal-verification.test.ts` (proves 160/160 Circuit 3-band safety states) |
| **C# / .NET** | Exhaustive BFS model check, **Dafny** (`.dfy` → C#), `Microsoft.Z3` | `templates/csharp-reference/OrderLifecycle.Tests/OrderFormalProofTests.cs` + `templates/csharp-reference/formal/OrderLifecycle.dfy` |
| **Rust** | **`stateright`** (exhaustive BFS model checker), **`kani`** (`#[kani::proof]`), **`loom`** / **`shuttle`**, **`verus`** | `templates/rust-reference/tests/formal_model_check.rs` (`stateright`) + `#[cfg(kani)]` harnesses in `templates/rust-reference/src/lib.rs` |
| **Python (3.12+)** | Exhaustive BFS model check + cross-coverage closure, `z3-solver`, `CrossHair` | `templates/python-reference/tests/test_formal_model_check.py` |
