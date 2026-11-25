# 01 — Complete Test & Verification Mechanism Index (42 Mechanisms, R0 → R8)

Every mechanism is tagged with its **Rung**, **Speed**, **Target Count / Budget**, **What Bugs/Slop It Kills**, **Blind Spots**, and **Recommended Tools**.

---

## Tier 0 — Instant Static & Harness Locks (`R0`, `< 2 s`, 100% of files)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V01` | **Formatters** | 100% files | Style drift, noisy diffs | Zero logic bugs | Prettier, `oxfmt`, `dotnet format`, `ruff format`, `rustfmt` |
| `V02` | **Anti-Slop & Escape-Hatch Lints** | 100% files | Chained `as`, `any`, `dynamic`, prod `.unwrap()`, prose excuse comments, lazy fallbacks | Business logic, multi-step state | `oxlint`, `dmmulroy/anti-slop`, `vstack no-comments`, Roslyn `VStack.Analyzers`, `clippy`, `ruff` |
| `V03` | **Test-Smell Lints** | 100% tests | Module mocks / heavy test doubles, sleeps, retries, `.only`/`.skip`/`[Ignore]`/`#[ignore]`, `if (...) expect(...)`, multi-status asserts, nondeterministic clock/RNG | Semantic wrong expected values | `@interfere/landmines`, `vstack scan`, Roslyn `VSTACK004` |
| `V04` | **Harness, CI Anti-Cheat & Oracle Locks** | Repo-wide | Editing locked specs/tests, conflicting `AGENTS.md`/skills, `continue-on-error: true`, `|| true`, `--no-verify`, `pull_request_target`/widened `permissions`, missing `timeout-minutes`/`concurrency`, `<NoWarn>`, blanket `#[allow]` | Logic correctness inside allowed paths | `vstack diff-cheats`, `vstack scan`, `CODEOWNERS`, `lefthook` |

---

## Tier 1 — Types, Deep-Module Structure & Diff Hygiene (`R1`, `1 – 10 s`, 100% of files)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V05` | **Constructive Type Discipline & Explicit State Machines** | 100% files | Illegal states, boolean soup, optional state bags, scattered mutations, non-exhaustive switches, swapped primitive IDs, unparsed boundary payloads | Runtime I/O without boundary schemas | `tsgo`/`tsc --strict`, Roslyn `VSTACK002`, Rust `enum` + `wildcard_enum_match_arm = "deny"`, Python `mypy --strict` + `assert_never`, `vstack state-machines` |
| `V06` | **Deep-Module Structural Lints** | 100% files | `field-leak`, `shallow-module`, `module-cycle`, `tangle`, `wide-directory`, `long-file`, `no-prefix-cluster`, `max-exports-per-module` | Runtime behavior | `deslop-please` (SCIP), `@interfere/landmines`, `oxlint-plugin-go-internal`, `vstack` |
| `V07` | **Architecture Fitness & Auto-Shrinking Ratchets** | 5–15 rules/repo | Layer violations (`domain → db/ui`), circular deps, dead files/exports, exact clones, brownfield regression creep | Runtime correctness | `dependency-cruiser`, `NetArchTest`, `ArchUnit`, `knip`, `jscpd` (≤5%), Packwerk, `vstack scan --ratchet` |
| `V08` | **AST Test-Quality, Complexity & Bloat Gates** | 100% diffs | Constant/self-derived assertions (`expect(f(x)).toBe(f(x))`), high CRAP hotspots, trivial-function test bloat, mega-PRs | Subtle oracle errors | `vstack classify`, `crap`, `cccc ≤ 5` floor, 400 net test-line ratchet, 800-LOC PR ceiling |

---

## Tier 2 — Pure Logic, Data Tables & Stateless Oracles (`R2`, `10 ms – 2 s`, diff-selected)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V09` | **Tests-as-Data Tables (JSON / CSV / YAML)** | 3–10 tables/service (20–100 rows each) | Missing permission/pricing/validation matrix cells; unreadable boilerplate tests; agent test drift | Multi-step state transitions | Declarative `.json`/`.csv`/`.yaml` fixtures + `it.each`, xUnit `[Theory]`/`[MemberData]`, `pytest.mark.parametrize`, Rust data runner |
| `V10` | **Focused Seam Unit & Error-Leaves-State Tests** | 10–40 tests/service *(0 for `cccc ≤ 5`)* | Normal & boundary rules; partial state corruption when a rule throws; pre-fix fail-to-pass bug repros | Broad input spaces, cross-boundary wiring | Bun / Vitest, xUnit, pytest, `cargo test` |
| `V11` | **Approval / Projection Tests (Scenarios & Logs)** | 3–15 approved fixtures/service | Subtle regressions in serialized outputs (HTML projections, SQL, ASTs, legacy behavior) | Rubber-stamping `--update` without review | `Insta`, `ApprovalTests`, `Syrupy`, diffable printers |
| `V12` | **Stateless Property-Based Testing (PBT)** | 2–8 properties/domain core (100–500 inputs each) | Edge cases humans never write (NaN, Unicode, empty, overflow, round-trip, idempotence, monotonicity) | Multi-step stateful sequences | `fast-check`, `FsCheck`, `proptest`, `Hypothesis` |
| `V13` | **Differential & Metamorphic Oracle Tests** | 1–3 harnesses/rewrite or optimizer | Rewrite/optimizer drift (new vs old/brute-force reference); no-oracle domains (search/ML filter monotonicity) | Shared bugs in both implementations | Dual-runner *Tests as Data*, `SQLancer`, custom differential harness |

---

## Tier 3 — In-Process Stateful, Boundaries, Contracts & Twins (`R3`, `0.2 – 5 s`, #1 E2E Killer)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V14` | **Stateful Model-Based Testing (MBT)** | 1 state-machine model per aggregate/workflow (100–500 sequences) | Unexpected action interleavings corrupting state; shrinks 50-step bugs to 3 steps | Pure CSS/visual layout; useless if model mirrors SUT complexity | `fast-check` `fc.commands`, `FsCheck.Experimental`, `proptest` / `proptest-state-machine`, `Hypothesis RuleBasedStateMachine` |
| `V15` | **Constrained External Test DSL + Side Channel** | 1 DSL per stateful product surface (10–30 scenarios) | Agents writing weak assertions; slow UI setup; UI/DB state divergence (`THEN page` + `THEN model`) | Runner bugs (protect runner separately) | Bespoke text parser + non-prod side channel + state printer |
| `V16` | **Subcutaneous / Component UI Tests** | 1 suite per critical screen + 1 all-states fixture page | Loading/empty/error/data states, keyboard focus, a11y roles/labels, user interactions without backend flake | Cross-origin headers, real backend wiring, full-page CSS | Testing Library, Playwright CT, Storybook, strict MSW (`onUnhandledRequest: "error"`) |
| `V17` | **In-Process Service Host Pipeline Tests** | 1 suite per API surface | Routing, middleware, model binding, JSON serialization, auth/tenant denial without container overhead | Real SQL engine behavior, real broker transport | `WebApplicationFactory<T>`, `TestServer`, Hono `app.request`, `tower::ServiceExt::oneshot`, FastAPI `TestClient` |
| `V18` | **Contract & Supported-Version Matrix Tests** | 1 contract per producer↔consumer edge | Breaking JSON/event shapes, old-UI/new-API & old-device/new-schema incompatibilities | Multi-hop semantic workflows, DNS/TLS | Pact, OpenAPI / `Schemathesis`, AsyncAPI, Protobuf `buf` |
| `V19` | **Digital Twins, AI Emulators & MITM Proxies** | 1 local twin per external 3rd-party/LLM API | Flaky/rate-limited 3rd-party sandboxes & expensive LLM eval loops (deterministic streaming, tool calls, latency, errors) | Twin drift vs real vendor API (calibrate with `V39`) | Local HTTP twins, `wiremock`, `respx`, `@emulators/ai`, `getsentry/roach` |
| `V20` | **Reachability / `sometimes` Invariants** | Attached to every MBT / DST / formal invariant | Vacuously green invariants where the error/recovery/edge branch never executed | Needs meaningful workloads to trigger | Antithesis `always` / `sometimes` / `reachable` / `unreachable`, `stateright` `Property::sometimes` |

---

## Tier 4 — Isolated Real Engines, Dry-Run & Deterministic Sim (`R4`, `2 – 30 s`, PR slices)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V21` | **Real DB, Seeded Migration & Bus DLQ Integration** | 1–3 DB slices/repo · 1 migration test/change · 1 bus DLQ/topic | Real SQL/locks/constraints, old-schema data loss on upgrade, duplicate delivery & dead-letter counts, real tenant isolation | Startup overhead (cut via DB schema snapshots) | Testcontainers, PGlite, `sqlx::test`, EF `MigrateAsync`, `alembic` |
| `V22` | **Deterministic Simulation Testing (DST)** | 1 simulation harness per distributed subsystem | Packet drops, partitions, crashes, clock skew, retry storms — 100% reproducible from a single RNG seed | Requires injectable clocks/network/disk I/O | `Turmoil` (Rust), FoundationDB Flow, TigerBeetle VOPR, Antithesis |
| `V23` | **Dry-Run / Plan-Diff Verification** | 1 dry-run per IaC / migration / batch pipeline | Broken IAM, destructive schema drops, bad K8s/Terraform config before touching live envs | Dry-run code path can diverge from real apply | `terraform plan`, `kubectl --dry-run=server`, rolled-back SQL migration dry-runs |

---

## Tier 5 — Deep Exploration, Formal Verification, Mutation & Circuits (`R5`, `30 s – 15 m`, diff/nightly)

| ID | Mechanism | Budget | Catches | Blind Spots | Tools |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `V24` | **Targeted Mutation & Property-Catalog Mutation** | Critical/changed auth, money, retry, state files (≥85–90% kill rate) | Fake 100% coverage; properties that pass because they never notice defects | Too slow repo-wide; equivalent mutants | StrykerJS, Stryker.NET, `cargo-mutants`, `mutmut`, PITest |
| `V25` | **Formal Verification, Sync-Commit Drift & SMT** | 1 spec/model check per concurrency/protocol/state core | Deadlocks, race conditions, lock-free bugs, domain invariant violations across *all* reachable states, stale specs passing on changed code | Verifies the model/bounded scope, not unmodeled glue | `Quint` (`.qnt` → ITF traces → MBT), `TLA+` / `everystate`, `Stateright`, `Kani`, `Dafny`, `Z3`, `Loom`/`Shuttle`, `vstack formal-sync` |
| `V26` | **Autonomous State-Space UI/TUI Search, Fuzzing & Catching JiTTests** | 1 Bombadil/web or TUI app · 1 fuzz target/untrusted parser · PR-time JiTTests | Unscripted web & TUI state bugs; parser crashes/OOMs; PR-specific regressions without committed debt | Needs sanitizers, invariants, or intent oracle | `antithesishq/bombadil`, `cargo-fuzz`, `libFuzzer`, `SharpFuzz`, `Atheris`, `Jazzer.js` |
| `V27` | **Visual Regression, Optical Alignment & Verified Security Audits** | Critical screens & PR UI diffs + additive security ledger | CSS overlap, clipping, contrast, off-grid layout; confirmed vs disproved security vulns | Animations need freeze; security audits need fresh disprover | Playwright visual diffs, Chromatic, Argos, fresh-context disprover audits |
| `V29` | **90/10 BYO System 1 Circuits & Improvement Classifiers** | Bounded round-robin sample (20–100 candidates/repo) + 90% deterministic short-circuit | Fast structured triage of test value, PR change risk, instruction→lint promotion, and performance optimization families | Raw-code System 1 models hallucinate without static facts; **must** pair with static corroboration, 3-band thresholds, explicit abstention, and holdout calibration | `vstack circuit`, `vstack classify` (`jev`, `laya`, `local`, `command`, `fixture`) |

---

## Tiers 6–8 — Capacity, Thin Golden-Path E2E & Live Production (`R6 – R8`)

| ID | Mechanism | Rung | Budget | Catches | Tools |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `V28a` | **Comparable Perf, 7-Question Bench Vetting & Load** | R6 | 1 bench/hot path · 1 load profile/service | Latency/memory/bundle regressions, untuned/no-op benchmark illusions, burst/soak leaks, flaky test retry masking | `tinybench`, `BenchmarkDotNet`, `criterion`, `pytest-benchmark`, `k6`, `NBomber`, 7-question benchmark checklist |
| `V28b` | **Thin Golden-Path E2E, App-Drive Hygiene & Hardware Proof** | R7 | **Strictly 5–15 critical journeys/app** | Real browser + real backend + real OAuth/CORS/webhooks + fresh-read persistence; Launch→Doctor→Drive→Evidence→Teardown hygiene; physical device/firmware | Playwright (PR-filtered), project-local `verify-<app>` skill, explicit hardware vs sim split |
| `V28c` | **Live Production Verification & Recovery** | R8 | **3–10 synthetics/app** + wide events | Prod-only traffic skew, TLS/DNS/3rd-party drift, rollback & 24h regret-free merge rate | OpenTelemetry wide events + tail sampling, GoReplay shadow traffic, canary rollouts, Chaos Mesh |

---

## Cross-Discipline Zero-Defect Additions (`V30`–`V42`, Lean / Silicon / Safety-Critical / Performance)

| ID | Mechanism | Rung | Origin | Budget | Catches | Tools |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `V30` | **Static Domain-Crossing Analysis (CDC/RDC)** | R1 | Silicon CDC/RDC | 100% files (`< 5 s`) | Wall-clock math in durations/TTLs, untrusted→sink taint, cross-tenant static caches, missing epoch fencing | `vstack` `cdc-wall-clock-duration`, branded/newtype wrappers, `clippy.toml` `disallowed-methods`, Semgrep taint |
| `V31` | **Static Execution Bounds & Hot-Path Zero-Alloc** | R1–R2 | NASA JPL · DO-178C WCET | 100% critical/hot files | Unbounded loops/recursion, ReDoS, unbounded payloads, steady-state GC/heap churn | `vstack` `unbounded-loop-risk`, `.max()` schemas, `ClrHeapAllocationAnalyzer`, `dhat`/`assert_no_alloc`, `RegexOptions.NonBacktracking` |
| `V32` | **Executable FMEA Control Plan & Bidirectional Traceability** | R1 | AIAG FMEA · DO-178C | 1 `.verification/control-plan.json`/svc (`< 2 s`) | Defects by omission (high-severity seam with no R0–R4 control), orphaned controls, unintended functionality | `vstack scan` (`fmea-high-severity-rung`, `fmea-orphaned-control`, `traceability-unverified-requirement`) |
| `V33` | **Automated Red-Before-Fix & A3 Escape Ratchet** | R1–R2 | TPS A3 · Shingo Poka-Yoke | Bugfix PRs (`2–15 s`) + `.verification/escapes.json` | Theater regression tests already green on unfixed base; repeat defect classes (`>= 2×`) lacking R0/R1 Poka-Yoke | `vstack red-before-fix --base <ref> --test-cmd "<cmd>"`, `vstack scan` (`a3-repeat-defect-no-poka-yoke`) |
| `V34` | **Critical-Decision MC/DC Independence Tables** | R2 / R5 | SQLite TH3 · DO-178C | Critical auth/safety/billing compound predicates (`< 1 s`) | Masked/dead sub-conditions inside compound boolean guards with 100% line/branch coverage | `vstack mcdc "<expr>"` ($N+1$ table generator) + targeted boolean-operator mutation at R5 |
| `V35` | **Taguchi Orthogonal Covering Arrays & Noise Invariance** | R2–R3 | Taguchi Robust Design | 1–3 covering arrays + 1 6-point noise wrapper (`< 2 s`) | Multi-flag/config interaction bugs + DST/Turkish locale/key-order/cold-cache sensitivity | Microsoft PICT / NIST ACTS covering arrays + reusable outer-array noise harness |
| `V36` | **Runtime Jidoka Assertions & Inline Temporal Monitors (SVA)** | R1 · R3–R8 | TPS Jidoka · Silicon SVA · JPL/TigerStyle | `>= 2` release-active invariants/critical fn + passive temporal monitors | Silent mid-pipeline corruption, release-stripped asserts, transient intermediate violations (4 ms dual-lease) | `vstack` `no-release-stripped-assert`, fail-closed Andon trip proofs, OTel / `DiagnosticListener` / `tracing::Layer` temporal observers |
| `V37` | **Functional Cross-Coverage Closure & Swarm / Cleanroom** | R3 · R5–R6 | Silicon UVM · Swarm · Cleanroom | 1–3 `Covergroup`s/state machine (100% legal bins, 0 illegal) | Uncovered deadly intersections (`retrying × failover × full`), destructive commands starving deep states, uncertified MTTF | Declarative `Covergroup` cross-bins, Swarm `p≈0.5` command subsetting, Cleanroom Markov operational profiles |
| `V38` | **Relational Non-Interference (2-World Multi-Tenant)** | R3–R4 | seL4 Non-Interference | 1 dual-world suite/tenant boundary (`1–15 s`) | Emergent cross-tenant leaks via shared caches, static singletons, counts, or error oracles | 2-world self-composition harness (`obs(W1, B) === obs(W2, B)` with arbitrary Tenant A mutations in W2) |
| `V39` | **Deterministic `1..N` Fault, Torn-Write & Bit-Flip Sweeps + Twin Calibration** | R4 | SQLite OOM/IOERR · Silicon SEU · Shingo MSA | 1 sweep/durable store (`5–30 s`) + nightly twin probe | Leaked locks/FDs on `k`-th alloc/IO failure, half-flushed WAL crash loops, silent bit-flips, twin-vs-live drift | Counter-injected `1..N` fault sweeps (`fail-rs`/Polly/FaultingFs), torn-write recovery, CRC/AEAD bit-flip tests, twin calibration |
| `V40` | **Formal Logic Equivalence Checking (Code-to-Code LEC)** | R5 | Silicon LEC | 1 harness/critical optimizer, compiler, or high-risk refactor | 1-in-$2^{32}$ behavioral divergence across refactors/optimizers missed by sampled differential tests | `Kani` (`#[kani::proof]`), `Dafny` equivalence lemmas, `z3-solver` (`unsat(ref(x) != opt(x))`) |
| `V41` | **PVT Corners, HALT Cliffs, SPC Drift, RTY & Boot BIST** | R6–R8 | Silicon PVT/HALT/BIST · Shewhart SPC · Crosby RTY | 2 PVT corners + HALT/SPC job + `< 500 ms` Boot BIST | Simultaneous hostile corners, cliff proximity (`OL ≈ DL`), creeping drift before SLA breach, hidden CI rework ($RTY$), bad deploys | `vstack spc <metrics.json>`, `computeRolledThroughputYield`, step-stress HALT cliff finder, fail-closed `--self-test` / `/readyz` Boot BIST |
| `V42` | **Empirical Big-O Scaling Tests & Algorithmic Perf Hygiene** | R1 · R2 / R6 | Asymptotic Scaling & Anti-Hack | 100% prod files (R1 lints) + 1 scaling curve/critical algorithm (`R2`/`R6`) | Accidental $O(N^2)$ loop scans/shifts, N+1 I/O in loops, per-iteration regex/deepcopy, GC-disable benchmark cheats, and hardware-invariant asymptotic regressions ($\hat{\alpha}_{\text{time}}, \hat{\beta}_{\text{space}}$) | `vstack scan` (`perf-quadratic-loop-scan`, `perf-nplus1-io-in-loop`, `perf-loop-compile-or-deepcopy`, `perf-anti-cheat`), `vstack big-o <samples.json>`, `measureEmpiricalBigO`, `vstack circuit run perf-architecture-advisor` |
