---
name: veristack
description: "Zero-defect verification across 9 rungs (R0 static locks to R8 production) in any language. Use when designing checks for a feature, pushing slow or bloated tests down the ladder, enforcing explicit state machines and test integrity, or locking down an escaped bug."
---

# Veristack

Select, author, and push down verification checks across 9 rungs (`R0` to `R8`) in any programming language.

> **Prime Directive:** Place every check on the lowest rung that preserves its exact failure mechanism. Static types, deep modules, and fast deterministic checks cut CI time, flake rate, and agent token burn simultaneously.

## Shared Vocabulary

Use these terms consistently across plans, PR evidence, and reviews:

- **Rung (`R0`–`R8`)**: verification tier ordered by speed and determinism.
- **Push-down**: moving a check to a lower, tighter rung without losing the failure mechanism it guards.
- **Seam**: the public interface where callers and tests observe behavior without reaching inside.
- **Oracle**: an independent source of truth (spec, literal, data table, reference model) that can disagree with buggy code.
- **Tight**: fast (seconds), deterministic, and single-command repeatable.
- **Red-before-fix**: a bugfix check proven to fail on the unfixed base commit and pass on the fix (`vstack red-before-fix`).
- **Two-Edit Test**: break the behavior and the check goes red; refactor internals keeping behavior and the check stays green.
- **Jidoka**: release-active invariants inside production code that halt fail-closed on the first corrupt unit.

## The 9-Rung Ladder

| Rung | Layer | Target Speed | Primary Job |
| :---: | :--- | :--- | :--- |
| **R0** | Static, Anti-Slop & Locks | `< 2 s` | Format, `no-comments`, escape-hatch bans, test integrity, anti-cheat diff |
| **R1** | Types, State Machines & Structure | `1–10 s` | Strict compiler, closed sum-type state machines, deep modules, CDC/bounds, FMEA plan |
| **R2** | Pure Logic, Tables & Stateless Oracles | `10 ms–2 s` | Tests-as-Data tables, MC/DC tables, stateless PBT, differential oracles |
| **R3** | Stateful MBT, Host, Component, Contracts & Twins | `0.2–5 s` | Primary E2E replacement (~80%): Stateful MBT, cross-coverage, in-process host, wire contracts, strict twins |
| **R4** | Real Engines, Migrations, Faults & DST | `2–30 s` | Real DB/migrations, real broker DLQ, `1..N` fault/torn-write sweeps, seeded DST |
| **R5** | Formal, Mutation, Fuzzing & 90/10 Circuits | `30 s–15 m` | Exhaustive model checks (`Quint`/`Stateright`/`Kani`/`Dafny`/`Z3`), diff mutation, fuzzing, `vstack circuit` |
| **R6** | Empirical Big-O, SPC, RTY & Load | `2–30 m` | Scaling exponents (`vstack big-o`), SPC drift (`vstack spc`), Rolled Throughput Yield, load/soak |
| **R7** | Thin Golden-Path E2E & Hardware Proof | `2–15 m` | Strictly 5–15 real end-to-end journeys max; separate physical hardware proof from simulation |
| **R8** | Live Production & Boot BIST | Continuous | `< 500 ms` fail-closed Boot BIST, 3–10 synthetics, canary/shadow verification, tail-sampled telemetry |

## Workflow (Execute in Order)

### Phase 0: Measure Ground Truth

Run `vstack scan . --json` before proposing or editing tests (on brownfield repos, pair with `--ratchet .verification/ratchet.json`; see `vstack --help` for `no-comments`, `state-machines`, `diff-cheats`, `formal-sync`, `red-before-fix`, `mcdc`, `spc`, `big-o`, and `circuit`).

- **Done when:** you have the scanner's rung coverage, cheat/error counts, and ranked push-down candidates in hand. Clear all existing `cheat`, `no-comments`, `no-implicit-state-machine`, and `formal-spec-stale` errors before adding new checks.

### Phase 1: Agree Seams & Minimum Valid Rung

For every requirement, bugfix, or test above `R2`:

1. Name the failure mechanism in one sentence (*what wrong outcome, and what minimum boundary is required for it to exist?*).
2. Walk the 4 gates and stop at the first **YES**:
   - **Q1 (`R0`/`R1`):** Can a deep module, closed sum-type state machine, strict compiler option, or custom lint rule (`Rule / Why / Fix`) prevent the defect statically? Build the type/lint + red-green proof and delete the runtime test.
   - **Q2 (`R2`):** Pure calculation, validation, parsing, or transition matrix? Extract a pure seam and write one declarative Tests-as-Data table or PBT (skip trivial wrappers with no branching).
   - **Q3 (`R3`):** Multi-step interleavings → Stateful MBT + cross-coverage. HTTP routing/auth → In-process Host. Wire shape → Contract + strict Twin. UI states/a11y → Component UI + strict network interceptor.
   - **Q4 (`R4`–`R7`):** Real SQL/migrations/bus DLQ → real `R4` engine. Distributed races/crashes → `R4` DST or `R5` formal model. Real OAuth/CORS/webhooks/hardware → `R7` (within the 5–15 journey cap).
3. Match dependency seams: absorb in-process helpers into deep modules; keep local stand-ins internal; use Ports & Adapters for remote owned services; inject typed SDK ports backed by strict twins for external vendors.

- **Done when:** every target seam is listed with (a) what it catches, (b) what it misses, and (c) its minimum valid rung. Confirm seams with the user before writing tests for a new feature.

### Phase 2: Author & Lock the Oracle

1. Express matrices as declarative `.json`/`.csv`/`.yaml` tables and compound security/billing guards as MC/DC tables (`vstack mcdc`).
2. Author oracles from independent specs/literals (never recompute expected values with production formulas).
3. Enforce hard boundary guardrails by replacing each anti-pattern with its target form:
   - Keep SQL, migrations, and broker DLQ tests at `R4` against real engines (never mock DB/storage below `R4`).
   - Model lifecycle state as a closed sum type with one `transition(state, event)` boundary and exhaustive dispatch.
   - Keep production invariants release-active (`InvariantViolationError` / checked `if (!ok) throw`), replacing `Debug.Assert`, `debug_assert!`, and bare Python prod `assert`.
   - Use Design for Testability (injectable clock/RNG/storage, domain telemetry, `< 500 ms` Boot BIST) instead of `*ForTesting` backdoors.
   - Await explicit signals or web-first locators instead of sleeps, retries, `continue-on-error: true`, or `|| true`.
   - For high-risk surfaces, run Independent Verification (IV&V) by dispatching a **fresh-context subagent** to audit spec vs implementation separately.

- **Done when:** every new or moved check has one primary owner at its strongest seam, passes the Two-Edit Test, and touches zero locked oracle files during a pure refactor.

### Phase 3: Prove Red → Green & Prune

1. For bugfixes, prove `vstack red-before-fix . --base <ref> --test-cmd "<cmd>"` fails on the unfixed base and passes on the fix. Record repeat defect classes (`>= 2×`) in `.verification/escapes.json` and promote them to `R0`/`R1`.
2. For new checks or push-downs, inject one controlled fault (or run diff mutation) to confirm the check goes **red**, restore, and confirm **green**.
3. Run the repo's full static + test gate (`vstack scan . --fail-on-cheats`, plus `vstack formal-sync . --fail` when formal models cover touched code and `--ratchet` on brownfield repos), delete redundant shallow tests replaced by stronger lower-rung checks, and emit a compact evidence line per moved/added check: `[ID | Old → New Rung | Failure Mechanism | Controlled-Fault Result | Residual Gap]`.

- **Done when:** `0` errors, `0` cheats, `0` prose comments, `0` implicit state machines, controlled-fault red→green is confirmed, and redundant higher-rung tests are pruned.

## Disclosed References (Load Only the Active Branch)

Load **only** the language guide matching the current repository:

| Language | Guide |
| :--- | :--- |
| **TypeScript / JavaScript** | [references/languages/typescript.md](references/languages/typescript.md) |
| **C# / .NET** | [references/languages/csharp.md](references/languages/csharp.md) |
| **Rust** | [references/languages/rust.md](references/languages/rust.md) |
| **Python (3.12+)** | [references/languages/python.md](references/languages/python.md) |

Load **only** the topic reference matching your task branch:

| Branch / Need | Reference |
| :--- | :--- |
| Choosing among all 42 mechanisms (`V01`–`V42`), budgets, and blind spots | [references/01-test-and-verification-index.md](references/01-test-and-verification-index.md) |
| Configuring `R0`–`R1` anti-slop, test-integrity, structural, or custom lint rules | [references/02-linter-and-antislop-stack.md](references/02-linter-and-antislop-stack.md) |
| Routing a failure mechanism, sizing test counts, cutting CI wall time, or running an audit/push-down | [references/03-pushdown-protocol-and-budgets.md](references/03-pushdown-protocol-and-budgets.md) |
| Engineering lineage and public citations | [references/04-source-patterns-digest.md](references/04-source-patterns-digest.md) |
| Writing a `Quint`/`TLA+`/`Stateright`/`Kani`/`Dafny`/`Z3` formal check (`R5 / V25`) | [references/05-formal-verification.md](references/05-formal-verification.md) |
| Running or wiring 90/10 BYO System 1 circuits (`vstack circuit`) | [references/06-system1-circuits.md](references/06-system1-circuits.md) |
| Applying Lean, Silicon, Safety-Critical, or Empirical Big-O practices (`V30`–`V42`) | [references/07-zero-defect-cross-discipline.md](references/07-zero-defect-cross-discipline.md) |
