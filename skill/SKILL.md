---
name: veristack
description: Select, author, lint, and push down verification checks across the universal 9-rung ladder (R0 static/linters to R8 production) in any programming language to maximize zero-defect assurance while minimizing CI time, test bloat, and token usage. Use when designing a system's verification strategy, deciding which check to write for a feature or bugfix, shrinking slow E2E or bloated unit suites, enforcing explicit state machines and anti-slop/test-integrity guardrails, or auditing test quality. Do NOT use for generic prose editing or running an already-wired CI command without changing verification strategy.
---

# Universal Verification Stack & Push-Down Ladder

> **Prime Directive:** Push every check as far **down** the ladder toward **R0** (faster, smaller, more deterministic) as possible **without losing the failure mechanism**. Maximize module depth and static/compiler enforcement so **CI runtime**, **flake rate**, and **agent token usage** stay minimal — in **any language**.

## Step 0 — Run the Deterministic Scanner First

Before proposing or editing any tests, run `vstack` to get ground-truth rung holes, anti-cheat violations, `no-comments` findings, implicit state machines, structural smells, and ranked push-down opportunities:

```bash
vstack scan . --json
vstack classify . --max 40
vstack circuit list
vstack circuit run test-triage . --provider fixture
vstack no-comments . --fail
vstack state-machines . --fail
vstack diff-cheats . --base HEAD --fail
vstack red-before-fix . --base HEAD --test-cmd "<targeted test>"
vstack mcdc "isAdmin || (isOwner && !isSuspended)"
vstack spc ./metrics.json --fail
vstack big-o ./scaling.json --max-time-exp 1.35 --fail
```

Fix all `cheat`, `no-comments`, and `no-implicit-state-machine` errors first, then act on `pushDownOpportunities` and `rungs[].gaps` using the universal protocol below.

---

## Universal Principles (Language-Agnostic — Always Apply)

1. **Ladder of Enforcement & Dual Containment:** Deep Modules / Architecture → Strict Algebraic Types → Compiler / Static Linter (with `Rule / Why / Fix`) → Executable Test / State Model → Formal Proof → Probabilistic AI Review → Human Review last. Every bugfix must prove **Red-Before-Fix** against its merge-base (`vstack red-before-fix`), and any 2nd escaped defect class in `.verification/escapes.json` must be promoted to an R0/R1 Poka-Yoke check (`V33`).
2. **Pre-Agree Seams, DFT / Boot BIST ≠ Test Backdoors, Replace Don't Layer:** Every contract gets **one primary owner at its strongest boundary**. Ban `*ForTesting` test-only production backdoors, while explicitly requiring **Design for Testability (DFT)** and fail-closed `< 500 ms` production **Boot BIST** (`V41`): injectable clocks/RNG/storage, domain-event telemetry for passive temporal monitors (`V36`), and startup self-diagnostics that serve production reliability first. Delete redundant shallow unit tests whenever a stronger lower-rung check replaces them.
3. **The Two-Edit Test & Independent Verification (IV&V):**
   - *Break the behavior* → check **must fail** (proves an independent, non-tautological oracle).
   - *Refactor internals keeping observable behavior* → check **must stay green** (proves behavior-not-implementation).
   - Separate spec/oracle authoring from implementation on critical surfaces: author `.verification/control-plan.json` (`V32`), `V09` data tables, `V14` state models, and `REQ-*` IDs first, lock them, then implement.
4. **Explicit State Machines, Domain Crossings & Boundedness:** Never model lifecycle state with boolean flag soup, optional state bags, scattered mutations, or non-exhaustive/silent-wildcard dispatch. Enforce static **Domain-Crossing (CDC/RDC)** boundaries (`V30`: monotonic clocks for durations, taint sanitizers, tenant-scoped caches, epoch fencing tokens) and explicit static bounds on loops, recursion, queues, and boundary payloads (`V31`).
5. **Assert Positive & Negative Space in Production (Runtime Jidoka):** Never strip corruption-critical assertions in release builds (ban `Debug.Assert` / `debug_assert!` / bare Python `assert` in prod — `V36`). Mirror invariants across write↔read boundaries, attach passive inline temporal monitors (SVA) across R3–R7 runs, and halt fail-closed on the first corrupt unit.
6. **Tests as Data, Cross-Coverage Closure & Simultaneous Corners:** Express matrices as `.json`/`.csv`/`.yaml` tables (`V09`), Taguchi orthogonal arrays (`V35`), and MC/DC independence tables (`V34`). Never treat line coverage or nominal 1× pass/fail as sign-off: gate stateful cores on **100% legal `state × op × fault` cross-coverage bins + Swarm subsetting** (`V37`), verify **simultaneous hostile corners** (slow/tight + fast/race) + HALT margin cliffs + **SPC drift ($C_{pk} \ge 1.33$, Nelson rules)** before hard SLA breaches (`V41`).
7. **Oracle Lock, Anti-Cheat Diff, Zero Hidden Factory & Routine Pruning:** Never weaken, skip, retry-mask, or edit locked specs/oracles. Ban `continue-on-error: true`, `|| true`, `--no-verify`, unjustified suppressions, sleeps, and piping tests into `tail`/`head`. Track multiplicative **Rolled Throughput Yield ($RTY = \prod FPY_r$)** across rungs so retries and rework never hide behind "100% green final merges." Never fake a push-down below R4 by mocking real DB/migration/storage engines; prune stale tests before finishing.

---

## Universal R0–R1 Guardrail Contract (Every Language Must Enforce)

| Universal Rule | Failure Mode Prevented | Language-Agnostic Requirement |
| :--- | :--- | :--- |
| **`no-comments`** | Prose/excuse comments rotting out of sync with code | Ban prose comments; allow only `WARNING:`, `SAFETY:`, license headers, generated markers, and public API docs. |
| **`no-implicit-state-machine`** | Illegal states compiling and corrupting transitions | Ban: (1) boolean-flag lifecycle soup, (2) optional/nullable state-bag DTOs, (3) scattered direct state mutation outside a single transition boundary, (4) non-exhaustive or silent-wildcard state dispatch. |
| **`no-unsafe-escape-hatch`** | Bypassing the type system or memory/error safety | Ban type-erasure casts (`any`, `dynamic`, unchecked `unsafe`/`transmute` without `SAFETY:`), and prod crash shortcuts (`.unwrap()`/`.expect()`). |
| **`no-swallowing-catch` & `suppression-audit`** | Silently hiding failures or linter/compiler warnings | Ban empty catch / `Err(_)` swallow blocks and unjustified warning/lint suppressions; require warnings-as-errors in build config. |
| **`no-test-only-production-seam`** | Production code polluted solely for shallow unit tests | Ban `*ForTesting` / `*_for_testing` / `TestOnly` backdoors in production modules. |
| **`test-integrity` (Landmines)** | Flaky, tautological, or coverage-farming tests | Ban fixed sleeps, unseeded RNG/wall-clock reads, global env mutation, `true == true` / `f(x) == f(x)` / multi-status `[200, 404]` asserts, one-sided `if (...) assert`, unexercised tests, and skipped/retry-masked tests. |
| **`oracle-lock` & `diff-cheats`** | Weakening the gate instead of fixing the bug | Fail on diff hunks introducing skips, retries, `continue-on-error`, `|| true`, `--no-verify`, or disabled warning gates. |

---

## The Universal 9-Rung Stack & Target Test Budgets

Target counts are per **typical production service or app** (scale proportionally for monorepos; PR CI runs diff-reachable checks first).

| Rung | Universal Layer | Speed Budget | Target Volume | Primary Job |
| :---: | :--- | :--- | :--- | :--- |
| **R0** | **Instant Static, Anti-Slop & Locks** | `< 2 s` | **100% of files** (0 runtime tests) | Formatting, `no-comments`, `no-unsafe-escape-hatch`, `no-swallowing-catch`, `suppression-audit`, `test-integrity`, `oracle-lock` |
| **R1** | **Types, State Machines & Structure** | `1 – 10 s` | **100% of files** (0 runtime tests) | Strict compiler/typecheck (`warnings = error`), `no-implicit-state-machine`, architecture DAG / cycle & shallow-module checks, dead-code/duplication ratchets |
| **R2** | **Pure Logic, Data Tables & Stateless Oracles** | `10 ms – 2 s` | **10–40 focused tests + 3–10 data tables + 2–8 PBTs** | Pure domain rules, boundary & error-leaves-state invariants, declarative JSON/CSV/YAML matrices, Property-Based Testing (PBT), differential/metamorphic checks |
| **R3** | **Stateful MBT, UI Component, Host, Contracts & Twins** | `0.2 – 5 s` | **1 MBT/state machine · 1 contract/API edge · 1 host suite/API · 1 component suite/screen** | **#1 E2E Replacement Layer (~80% of E2E).** Multi-step interleavings via Stateful MBT, in-process HTTP/middleware host, wire-shape contracts, strict network twins, DOM/a11y |
| **R4** | **Real Engines, Migrations, Dry-Run & DST** | `2 – 30 s` | **1–3 DB slices/repo · 1 migration test/schema change · 1 bus DLQ/topic · 1 DST/distributed core** | Real SQL/locks/constraints, real schema migrations, real message-bus idempotency/DLQ, real auth/IaC dry-runs, seeded Deterministic Simulation Testing (DST) |
| **R5** | **Deep Exploration, Formal Verification, Mutation & System 1 Circuits** | `30 s – 15 m` | **1 formal spec/model check per critical state machine/protocol · 1 fuzz target/untrusted parser · targeted mutation · plug-and-play `vstack circuit`** | Exhaustive formal model checking (`Quint`/`TLA+`/`Stateright`/`Kani`/`Dafny`/`Z3`), fuzzing, targeted mutation (`>= 80–85%`), 90/10 JEV-style BYO System 1 circuits (`vstack circuit` / `vstack classify`) |
| **R6** | **Perf, Load Capacity & Suite Telemetry** | `2 – 30 m` | **1 benchmark/hot path · 1 load+spike+soak profile/service** | Comparable microbenchmarks, stress/soak profiles, first-attempt reliability ledger (zero green retries) |
| **R7** | **Thin Golden-Path E2E & Hardware Proof** | `2 – 15 m` | **Strictly 5–15 critical journeys/app** | Real browser/client + real backend + real OAuth/CORS/webhooks + fresh-read persistence; separate simulator vs physical hardware proof |
| **R8** | **Live Production Verification** | Continuous | **3–10 synthetics/app** + tail-sampled telemetry | Canary/staged exposure, shadow replay, chaos with guardrails, 24h auto-revert & regret-free merge rate |

---

## Universal 4-Gate Push-Down Decision Flow

For every new requirement, bugfix, or existing test above R2:

1. **Name the failure mechanism** in one sentence (*what wrong outcome, and what minimum boundary is required for it to exist?*).
2. **Drop down the 4 gates — stop at the first `YES`:**
   - **Q1 (R0/R1):** Can a deep module, closed algebraic sum type, strict compiler rule, or custom static analyzer (`Rule / Why / Fix`) make the defect impossible to compile or commit? → **Build the type/lint + red-green proof; delete the runtime test.**
   - **Q2 (R2):** Pure calculation, validation, parsing, or state transition matrix? → **Extract a pure seam; write 1 declarative Tests-as-Data table or PBT.** *(Skip trivial wrappers with no branching/invariants.)*
   - **Q3 (R3):** Stateful sequence/interleaving → **Stateful MBT**. HTTP routing/auth middleware → **In-process Host**. Service/event wire shape → **Contract + Twin**. UI DOM/error/a11y → **Component UI + Strict Network Interceptor**.
   - **Q4 (R4–R7):** Real SQL/migration/bus DLQ → **R4 Real Engine (never mock below R4)**. Distributed crashes/races → **R4 DST / R5 Formal Model**. Real CORS/OAuth/webhook/hardware wiring → **R7 (strictly within the 5–15 journey cap)**.
3. **Apply the Seam Check (4 dependency types):** In-process → absorb into deep module; Local stand-in → internal seam; Remote owned → Ports & Adapters (network in prod, in-memory in test); True external → injected port + strict wire twin.
4. **Verify Before Done:** Pass all R0/R1 static gates, verify the refactor touches prod only (Tests-as-Data invariant), inject **1 controlled mutant/fault** to prove the check goes red then green, and report runtime delta + residual gaps.

---

## Per-Language Implementations & References

Load **only** the language guide(s) matching the repository you are working in:

| Language | Static / Compiler Enforcement (R0–R1) | Runnable R0–R5 Proof | Language Reference |
| :--- | :--- | :--- | :--- |
| **TypeScript / JS** | `Oxlint` (`oxlint-no-comments.mjs`, `oxlint-explicit-state-machine.mjs`, `anti-slop`, `@interfere/landmines`), `tsgo`, `deslop-please`, `knip`, `vstack` | `tests/` + `lint/` in this repo | [references/languages/typescript.md](references/languages/typescript.md) |
| **C# / .NET** | Roslyn `VStack.Analyzers` (`VSTACK001`–`VSTACK004`), `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`, `dotnet format`, `vstack` | `templates/csharp-reference/` | [references/languages/csharp.md](references/languages/csharp.md) |
| **Rust** | `[lints.rust]` (`unsafe_code = "forbid"`, `warnings = "deny"`), `[lints.clippy]` (`all`, `unwrap_used`, `expect_used`, `panic`, `wildcard_enum_match_arm` = `"deny"`), `rustfmt`, `vstack` | `templates/rust-reference/` | [references/languages/rust.md](references/languages/rust.md) |
| **Python (3.12+)** | `ruff` (`S101` prod assert ban, strict lint + format), `mypy --strict` (`disallow_any_explicit`), `assert_never`, `vstack` | `templates/python-reference/` | [references/languages/python.md](references/languages/python.md) |

### Extending to a New Language (e.g. Go, Java, Swift)
To onboard another language with full universal parity, add five pieces without duplicating core philosophy:
1. **R0/R1 Native Compiler/Linter Gate:** Turn warnings into errors and enforce `no-comments`, `no-implicit-state-machine`, `no-unsafe-escape-hatch`, `suppression-audit`, and `test-integrity` natively.
2. **Scanner Adapter in `src/`:** Register extension + state-machine adapter + test-smell/import/diff-cheat patterns in `vstack`.
3. **Runnable R0–R5 Reference Template:** Minimal domain state machine + JSON Tests-as-Data table + PBT + Stateful MBT + mutation gate under `templates/<lang>-reference/`.
4. **Red→Green Parity Tests:** Negative and positive fixtures in `tests/<lang>-parity.test.ts`.
5. **Language Guide:** Add `skill/references/languages/<lang>.md` and link it in the table above.

---

## Core Cross-Language Reference Index (Load Only What You Need)

| Need | Read |
| :--- | :--- |
| Full 42-item catalog of test & verification mechanisms (`V01`–`V42`), tools across languages, and blind spots | [references/01-test-and-verification-index.md](references/01-test-and-verification-index.md) |
| Universal R0–R1 linter architecture, anti-slop patterns, ratchets, and custom lint anatomy | [references/02-linter-and-antislop-stack.md](references/02-linter-and-antislop-stack.md) |
| Failure-mechanism routing table, forbidden push-downs, test-count sizing formulas & CI speedups | [references/03-pushdown-protocol-and-budgets.md](references/03-pushdown-protocol-and-budgets.md) |
| Source patterns distilled from *Tests as Data*, open-source linters, and verification literature | [references/04-source-patterns-digest.md](references/04-source-patterns-digest.md) |
| Universal & per-language Formal Verification (`Quint`/`TLA+`, `Stateright`, `Kani`, `Dafny`, `Z3`, `Loom`) | [references/05-formal-verification.md](references/05-formal-verification.md) |
| Plug-and-play JEV-style System 1 Circuits (`90% deterministic + 10% BYO System 1`: `jev`, `laya`, `local`, `command`, `fixture`) | [references/06-system1-circuits.md](references/06-system1-circuits.md) |
| Cross-discipline Zero-Defect Practices (`V30`–`V42`: Lean/TPS, Silicon/Hardware, Safety-Critical & Algorithmic Performance) | [references/07-zero-defect-cross-discipline.md](references/07-zero-defect-cross-discipline.md) |
