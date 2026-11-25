# 03 — Agent Push-Down Decision Protocol, Sizing Budgets & CI Speed

Use this playbook when (a) designing tests for a new system/feature, (b) auditing and shrinking an existing test suite, or (c) fixing an escaped bug.

---

## 1. Failure-Mechanism → Minimum Valid Rung Routing Matrix

**Rule:** Find the failure mechanism you fear, pick the **Minimum Valid Rung**, and refuse to put the test higher *or* lower.

| Failure Mechanism | Min Rung | Exact Verification Form | Never Put Here |
| :--- | :---: | :--- | :--- |
| Null deref, wrong field, missing enum branch, invalid state combo, swapped IDs | **R0 / R1** | Discriminated union, branded type, `tsgo`/Roslyn strict, `anti-slop` | Unit or E2E |
| Layer violation, `field-leak`, `shallow-module`, cycle/tangle, dead file, clone | **R0 / R1** | `deslop-please`, `arch-fitness`, `go-internal`, `knip`, `jscpd` | Prose in `AGENTS.md` or E2E |
| Lazy test (mocks, sleeps, retries, conditional expect, Tailwind class assert) | **R0** | `@interfere/landmines` + `vstack` `weak-asserts`/`test-discipline` | Code review comments |
| Pure math, pricing, parser, validation, permission matrix, error mutating local state | **R2** | **Tests-as-Data CSV/YAML table** or **PBT** (skip if `cccc ≤ 5` & no regex) | Component, Integration, or E2E |
| Complex output formatting (HTML template, SQL builder, AST, legacy behavior) | **R2** | **Approval / Projection test** (diffable text printer) | Browser E2E |
| Rewrite / query optimizer equivalence; search/ML ranking monotonicity | **R2** | **Differential / Metamorphic oracle** (same test data, 2 runners) | Hand-written examples |
| Multi-step user/API workflow, cache/cart/session/lock interleavings | **R3** | **Stateful MBT** (`fast-check` commands / `Hypothesis`) or **Constrained DSL** + `sometimes` reachability | Browser E2E |
| UI loading/empty/error/data rendering, form states, keyboard focus, a11y | **R3** | **Component UI** (Testing Library / Playwright CT + strict MSW) + all-states fixture page | Full-stack E2E |
| HTTP routing, middleware, serialization, `[Authorize]` policy attributes | **R3** | **In-process Host** (`WebApplicationFactory` / `supertest`) | Direct controller unit test (too low) or E2E (too high) |
| Producer/consumer JSON or event schema drift; old UI vs new API | **R3** | **Contract Test** (Pact / OpenAPI / AsyncAPI) + supported version matrix | Shared staging E2E |
| Flaky/rate-limited 3rd-party API (Stripe, mail, exchange) | **R3** | **Digital Twin** (local simulator) + `getsentry/roach` MITM cache proxy | Live sandbox in PR CI |
| Real SQL query/locks/constraints; EF/SQL migration preserving old rows | **R4** | **Testcontainers real DB** (1s schema snapshot) + seeded old-schema migration | In-memory DB / SQLite mock (too low!) or E2E (too high!) |
| Real message broker ack, serialization, `MaxDeliveryCount`, DLQ | **R4** | **Testcontainers real Bus** duplicate + failure redelivery test | Direct handler call (too low!) or E2E (too high!) |
| Distributed crash recovery, network partition, clock skew, retry storms | **R4 / R5** | **DST** (seeded virtual clock/net) or **Formal** (`TLA+`/`Everystate`) | Flaky multi-node staging E2E |
| IaC / IAM / destructive migration safety | **R4** | **Dry-Run / Plan-Diff** (`terraform plan`, `kubectl --dry-run=server`) | Manual staging deploy |
| Concurrency race condition, deadlock, lock-free invariant | **R5** | **Everystate / TLA+ `statechart` / Alchemy Z3 / Loom** | `sleep()` integration test |
| Untrusted parser/codec crash, panic, OOM, security vuln | **R5** | **Coverage-guided Fuzzing** (`cargo-fuzz` / `libFuzzer` / `Jazzer`) | Hand-written unit tests |
| Unscripted web-app state-space bugs | **R5** | **Bombadil** (~4.5k random actions/5m) | 100 scripted Playwright flows |
| CSS overlap, clipping, contrast, optical alignment | **R5** | **Visual Regression** (`/ui-diff`, `/gridlines`, Chromatic) | DOM text assertions |
| Weak assertions / fake 100% line coverage | **R5** | **Targeted Mutation Testing** (Stryker / `mutmut` on critical/changed diffs) | Adding more unit tests |
| Latency regression, memory/connection leak, burst/soak collapse | **R6** | **Comparable Perf** (`benchmark-checklist`) + **k6 Stress/Spike/Soak** | Single-request E2E |
| Real CORS, OAuth redirects, cookies, TLS, 3rd-party webhooks, physical hardware | **R7** | **Thin Golden-Path E2E (5–15 max)** + fresh-read persistence + explicit hardware proof | Mocked component test (too low!) |
| Prod-only traffic skew, failover, cert expiry, regret-free deploys | **R8** | **Shadow replay + Canary + Chaos + 3–10 Synthetics + 24h auto-revert** | Staging E2E |

---

## 2. The 4-Category Seam Model (From Matt Pocock `DEEPENING.md`)

When deciding where to put a test boundary during design or refactoring:
1. **In-process collaborator:** Absorb into one **deep module**. Test at the outer interface; **delete** old unit tests on swallowed shallow helpers (*replace, don't layer*).
2. **Local test stand-in exists** *(PGLite, in-memory FS, embedded SQLite with parity)*: Keep the seam internal (no port on external interface); run the stand-in inside the module's test suite.
3. **Remote but owned** *(your microservices / internal queues)*: Define a **port** (only if ≥2 adapters are justified: prod + test). Run R3 logic tests with an in-memory adapter + R3 contract test + R4 real-engine test.
4. **True external** *(Stripe, Twilio, external webhooks)*: Inject an **SDK-style port** (named typed methods like `chargeOrder()`, never generic `fetch(url, opts)`), backed by a **Digital Twin** or strict MSW in R3.

---

## 3. Forbidden Push-Downs (Hard Guardrails)

An agent MUST NEVER:
1. Push SQL constraints, collations, transactions, or migrations below **R4** (real DB engine).
2. Push message-broker acks, retries, or dead-letter handling below **R4** (real test bus).
3. Push routing, middleware, serialization, or `[Authorize]` checks below **R3** (real in-process host).
4. Claim a mocked-network R3 UI test proves persistence without R3 contract + R4 DB + ≥1 R7 fresh-read journey.
5. Claim simulator/Digital Twin proof counts as physical hardware/firmware proof.
6. Push a test down by weakening assertions or introducing `vi.mock` / test doubles.

---

## 4. Concrete Test-Count & CI-Time Budgets (By Repo Size)

| Repo Archetype | R0–R1 Static | R2 Pure/Tables/PBT | R3 MBT/Comp/Host/Contract | R4 Real Engine/DST | R5 Formal/Mut/Fuzz | R7 E2E Cap | Target PR CI Wall Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Pure Library / SDK** | 100% | 15–30 tests + 2–5 tables + 3–8 PBTs | 0–2 MBT + 1 API compat matrix | 0 | 1–2 fuzz + diff mutation | **0** | **< 20 s** |
| **Single Backend Service** | 100% | 10–30 tests + 3–6 tables + 2–5 PBTs | 1–2 MBT + 1 host suite + 1 contract/edge | 2–5 DB/migration/bus slices (+ 1 DST if distributed) | 1 formal/protocol + critical-diff mutation | **1–3** cross-service tasks | **< 45 s** (PR diff-selected) |
| **Web Frontend App** | 100% | 5–15 pure tests + 2–4 tables | 1 component suite/critical screen + 1 all-states fixture + 1 UI-API contract + 1 MBT | 0–2 real API read/write checks | 1 Bombadil + `/ui-diff` + `/gridlines` | **5–10** golden journeys | **< 60 s** (PR diff-selected) |
| **Full-Stack / Multi-Service Platform** | 100% | Per-service budgets above | Per-service + Digital Twins for 3rd-party | Per-service Testcontainers w/ 1s schema snapshots | Nightly fuzz/formal/Bombadil; PR diff mutation | **5–15** total golden journeys + hardware matrix | **< 90 s PR** / hourly full main |

### Test Bloat, Retention & CI Speed Controls
* **4-Question Authoring Gate:** Before adding any test, confirm: (1) observable behavior, invariant, or independent contract, (2) credible regression that breaks it, (3) **one primary owner at its strongest seam** (never replay the same bug at every crossed layer), (4) **zero test-only production backdoors** (no export/flag/wrapper with no production caller).
* **Useless Test Deleter + Simplification Pass:** Delete junk tests (self-comparisons, copied inventories, identifier-fragile source greps, fixtures fabricating receipts/order, tests checking deleted features stay deleted) **and** remove production complexity that only existed to satisfy them. Run a simplification pass targeting LOC / Halstead / `cccc`.
* **Retention Bar (Never Blindly Delete):** Preserve independent API, SDK, protocol, config, migration, storage, security, platform, default, prompt-byte, release, architecture, and observable-ordering contracts. Static/slow ≠ disposable; baseline failures may be real bugs to fix.
* **Triviality floor & line ratchet:** Skip unit tests for `cccc ≤ 5` cognitive complexity unless regex or critical invariant; cap net new test lines per PR (400 LOC) — prefer CSV/YAML tables and 1 PBT/MBT over 50 copy-pasted tests.
* **Verification stamping & commit gate:** Stamp every commit with how it was verified (including `"none"`). Roll out new gates in `off → observe → enforce` mode (with a 2-block session escape valve requiring explicit rationale). Cap agents at **2 CI rounds per task**; never pipe tests into `tail`/`head`. Track reviewer recall separately at *raw → post-verification → final* and tag findings `Important | Nit | Pre-existing`.
* **Diff-reachable PR speed vs. full-merge safety:** On intermediate PR pushes, run diff-reachable tests (`testscope` ~6% median, reverse-import + fixture watch graph, fail-closed fallback to full when unsure) — **and gate final merge / merge-queue on the full suite** (prevents affected-projects filters from silently skipping shards and reporting green; never put `paths:` filters on required status checks).
* **Statistical CI speedup validation:** Measure CI's *own* runs (never trust local timings), **≥5 comparable CI runs per side** (median + Hodges-Lehmann 95% interval + slowest/p95), **1 CI change per PR**, verify **test count by name** didn't drop, and never sum separate estimates linearly (off-critical-path fixes save 0s). Ask a human before spending money on bigger runners.
* **Container, cache & workflow speed:** Load DB schema snapshots (12s → 1–2s), `tsgo` typecheck, syntax-only Oxlint, Vitest `isolate: false` on safe lanes, time-balanced sharding, fold tiny setup-heavy jobs into 1–2 jobs, remove useless `needs:` chains, audit 10 GB cache eviction & parallel cache-key collisions, use prebuilt tool binaries instead of `cargo/go install`, blobless checkouts, Lefthook pre-commit (`< 2s`).

---

## 5. Anti-Cheating Gate & File-Change Matrix

Before claiming completion, verify:

| Task Type | Prod Code Changes? | Test Data (Tables/DSL) Changes? | Test Runner / Gates Change? |
| :--- | :---: | :---: | :---: |
| **Refactor prod code** | Yes | **NO** | **NO** |
| **New feature / bugfix** | Yes | Yes *(failing test committed first for bugs)* | **NO** |
| **Push down / harden tests** | Only declared pure-seam extraction | Yes | Only if adding new DSL/lint |
| **Extend DSL / Harness** | **NO** | Yes | Yes *(requires human review)* |

Plus:
1. **Controlled-Fault Proof:** Inject 1 plausible defect (or run targeted mutation) → confirm the check goes **red**, restore → confirm **green**.
2. **5-Step Blast-Radius Proof Ladder:** Push every safety claim for a risky change as far down the ladder as cheap and report where it stopped: (1) *Said so* (worthless) → (2) *Cited `file:line`* → (3) *Walked path step-by-step* → (4) *Ran real code that fails loud if wrong* → (5) *Reproduced in the running app*.
3. **7-Question Benchmark Vetting (`R6`):** Before reporting any speedup or perf claim, verify with run evidence: (1) named limiter (*why not 2×?*), (2) prod-tuned on both sides, (3) sanity-checked against physical bandwidth/CPU limits, (4) error/wrong-output count = 0, (5) `>= 5` alternating A/B runs with median + range, (6) end-to-end user-path share, (7) proof work actually executed inside the timed region.
4. **R7 App-Drive Hygiene:** Project-local E2E / live-app verification skills follow **Launch → Doctor (health check before first drive and after any failure) → Drive → Evidence (verified to survive cleanup) → Teardown (zero residue)**.
5. **Brownfield Ratchet Rollout:** Adopt `vstack scan . --ratchet .verification/ratchet.json` on legacy repos day 1; fail on any count increase *or* un-tightened count drop (`--update-ratchet`).
6. **PR Evidence Bundle:** Emit for each moved/added check: `[ID | Old Rung → New Rung | Failure Mechanism Preserved | Negative Control Result | Runtime Delta | Residual Gap]`.

---

## 6. Drop-In Agent Prompts

### A. Audit & Push Down an Existing Suite
> Call the Skill tool with "veristack", then read `references/03-pushdown-protocol-and-budgets.md`.
> Report first; edit nothing yet. Run `vstack scan . --json`, inventory every test file, and output:
> `[File/Test | Current Rung | Failure Mechanism | Target Min Rung | Proposed Form (Lint/Type/Table/PBT/MBT/Component/Host/Contract/R4/Delete) | Why No Lower | Est. Speedup]`.
> Flag every test failing the Two-Edit Test, every `vstack` anti-cheat/test-integrity violation, and any E2E beyond the 5–15 golden-path cap.
> Done when every test file in the repository is accounted for in the table; wait for approval before editing.

### B. Build Verification for a New Feature
> Call the Skill tool with "veristack". Before writing implementation code:
> 1. Propose the public seams under test (1 line each: what it catches, what it misses, target rung) and wait for confirmation.
> 2. Encode invariants in closed types and `R0`/`R1` lints first.
> 3. Express matrix rules as Tests-as-Data tables (`.json`/`.csv`/`.yaml`) and multi-step state as a Stateful MBT or Constrained DSL.
> 4. For high-risk surfaces, dispatch a fresh-context subagent to audit implementation against the locked spec independently.
> Done when every critical check goes red on a controlled fault, restores green, and `vstack scan . --fail-on-cheats` reports 0 errors.

### C. Promote a Bug/Incident Down the Ladder
> A defect escaped: `<describe defect>`.
> 1. Commit a minimal failing check at the lowest valid rung and verify `vstack red-before-fix . --base <ref> --test-cmd "<cmd>"` passes.
> 2. Log the escape in `.verification/escapes.json`. If this mistake class has occurred twice (`>= 2×`), promote it to a deterministic `R0`/`R1` type, linter rule (`Rule / Why / Fix`), or architecture check with a negative red→green fixture.
> 3. Fix the root cause, confirm green, and prune any prose rule in `AGENTS.md` now enforced by code.
> Done when red-before-fix is proven, repeat escapes have a linked `R0`/`R1` Poka-Yoke, and `vstack scan . --fail-on-cheats` exits 0.

### D. Weekly Bugfix Architecture Retro
> Inspect the last week of bugfix commits (`git log --since="7 days ago"`). Group defects by root class and propose the smallest architectural, type, or `R0`/`R1` lint change that would obviate the top recurring class entirely. Prove any proposed lint fails on the real historical bug commit before shipping.
