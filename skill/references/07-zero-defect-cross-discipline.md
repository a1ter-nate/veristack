# 07 — Cross-Discipline Zero-Defect Verification (`V30`–`V42`: Lean, Silicon, Safety-Critical & Performance)

Distilled from cross-discipline zero-defect research across **Lean Manufacturing / TPS**, **Hardware & Silicon (ASIC/FPGA)**, **Safety-Critical Software (NASA JPL, DO-178C, SQLite, TigerBeetle, Cleanroom, seL4)**, and **Asymptotic Performance Verification**.

---

## The 4 Convergent Zero-Defect Laws

1. **Always-On Internal Tripwires Beat External Post-Hoc Detection:** TPS (*Jidoka + Andon*), Silicon (*SVA inline temporal monitors + Boot BIST*), and NASA JPL / TigerBeetle (*production assertion density + paired write↔read assertions*) all embed active self-checking invariants **inside production**, halting on the **first corrupt unit**.
2. **Nominal 1× Pass/Fail Hides Cliffs and Creeping Drift:** Shewhart (*SPC control limits, Nelson rules, $C_{pk}$*), Taguchi (*orthogonal covering arrays + outer-array noise invariance*), and Silicon (*PVT simultaneous corners, CI guardbands, HALT Operating Limit vs Destruct Limit cliffs*) test **margins, drift-before-breach, and simultaneous hostile corners**.
3. **Code Coverage and Isolated `sometimes` Flags Miss Deadly Intersections:** Silicon (*UVM `state × op × fault` cross-coverage closure*), DO-178C / SQLite (*MC/DC compound-condition independence*), and Swarm Testing (*randomized command subsetting*) prove you must measure **interaction closure** and prevent destructive actions from starving deep states.
4. **Defects-by-Omission & Theater Tests Require Mechanical Traceability:** Automotive (*FMEA Control Plans*), DO-178C (*Bidirectional Traceability + IV&V*), and TPS (*Red-Before-Fix + A3 escape ratchet*) block shipping high-risk surfaces without controls, catch unintended agent functionality, and prove bugfix tests fail on the unfixed base commit.

---

## Automatable Checks Already Shipped Inside `vstack`

| Mechanism | `vstack` Enforcement / CLI | What It Catches |
| :---: | :--- | :--- |
| **`V30` Clock CDC** | `vstack scan` (`cdc-wall-clock-duration`) across TS, C#, Rust, Python | `Date.now() -`, `DateTime.UtcNow -`, `SystemTime::now().duration_since`, `datetime.now() -` / `time.time() -` in prod |
| **`V31` Execution Bounds** | `vstack scan` (`unbounded-loop-risk`) across TS, C#, Rust, Python | `while (true)` / `while True:` / `loop {` without a static iteration/fuel bound |
| **`V32` FMEA Control Plan & Bidirectional `REQ-*` Traceability** | `vstack scan` (`.verification/control-plan.json`) | Severity `>= 8` controls left above `R4`, deleted/orphaned `controlRef`s, and `REQ-*` IDs with 0 linked tests |
| **`V33` Red-Before-Fix & A3 Escape Ratchet** | `vstack red-before-fix . --base <ref> --test-cmd "<cmd>"` + `.verification/escapes.json` | Theater bugfix tests that already pass on unfixed base; repeat defect classes (`>= 2×`) without an R0/R1 `pokaYokeRef` |
| **`V34` MC/DC Independence Table Generator** | `vstack mcdc "<boolean expression>" [--json]` | Minimal $N+1$ truth-table rows proving every sub-condition independently flips the decision (and flags dead/redundant clauses!) |
| **`V36` Runtime Jidoka Release-Active Assertions** | `vstack scan` (`no-release-stripped-assert`) | `Debug.Assert` (C#), `debug_assert!` (Rust), and bare `assert` (Python prod, stripped by `-O`) |
| **`V41` SPC Drift & Rolled Throughput Yield** | `vstack spc <metrics.json> [--fail]` + `computeRolledThroughputYield` | Nelson Rule 2 (`>= 7` above mean), Nelson Rule 3 (`>= 6` monotonically worsening), $C_{pk} < 1.33$ headroom warning before USL breach, and $RTY = \prod FPY_r$ |
| **`V42` Empirical Big-O & Perf Hygiene** | `vstack scan` (`perf-quadratic-loop-scan`, `perf-nplus1-io-in-loop`, `perf-loop-compile-or-deepcopy`, `perf-anti-cheat`), `vstack big-o <samples.json>`, `vstack circuit run perf-architecture-advisor` | Hardware-invariant asymptotic time/space scaling regressions ($\hat{\alpha}_{\text{time}}, \hat{\beta}_{\text{space}}$), $O(N^2)$ loop scans/shifts, N+1 I/O in loops, per-iteration regex/deepcopy, GC benchmark tampering |

---

## Engineering Blueprints for `V35`, `V37`–`V40`, and Boot BIST

- **`V35` Taguchi Orthogonal Arrays & Noise Wrapper (`R2`–`R3`):** Generate minimal 2-way/3-way covering arrays (PICT/ACTS) for 6–15 config/flag axes + wrap core suites in a 6-point outer noise matrix (DST fold, `tr-TR`/`de-DE` locales, shuffled JSON keys, CRLF, cold/warm cache).
- **`V37` Functional Cross-Coverage & Swarm / Cleanroom (`R3`, `R5`, `R6`):** Attach a `Covergroup` (`state × action × fault`) to MBT/DST gating on **100% legal cross-bins and 0 `illegal_bins`**; randomly disable ~50% of commands per seed (Swarm mode) so `delete`/`cancel` don't starve deep states; drive R6 Markov traffic matrices from prod wide events.
- **`V38` Relational Non-Interference (`R3`–`R4`):** Execute identical Tenant B sequences in World 1 vs World 2 (injecting arbitrary Tenant A traffic only in World 2) and assert bit-for-bit identical Tenant B responses/state.
- **`V39` Deterministic `1..N` Fault, Torn-Write & Bit-Flip Sweeps (`R4`):** Sweep fallible alloc/IO call indices `k = 1..N` + torn-write crash prefixes + bit-flip corruption, asserting clean error recovery, zero leaked locks/FDs, and crash-prefix linearizability; pair with scheduled twin-vs-live calibration probes.
- **`V40` Formal Logic Equivalence Checking (`R5`):** Symbolically prove `∀x: ref(x) ≡ opt(x)` across refactors/optimizers (`Kani`, `Dafny`, `Z3`).
- **`V41` PVT Corners, HALT Cliffs & Boot BIST (`R6`–`R8`):** Verify simultaneous *Slow/Tight* and *Fast/Race* corners, find exact `OL` vs `DL` cliffs with `<= 75%` CI guardbands, and ship a `< 500 ms` fail-closed production **Boot BIST** (`--self-test` / `/readyz`) verifying config/schema/crypto/downstream boundary scans at startup.

---

## High-Yield Production Escape Playbooks (Mined From Real Incident Histories)

- **Tri-State Document Query Invariant (`R2`):** Whenever querying optional/backfilled boolean flags in document stores, test every filter/count query against a 3-record fixture `{ missing, false, true }` so `.where(field, "==", false)` cannot silently drop legacy documents or diverge list vs count totals.
- **Contract, OpenAPI & DB-Index Sync (`R3` / `vstack formal-sync`):** Register `contractChecks` in `.verification/control-plan.json` pairing `routes`/`dtos` → OpenAPI/consumer-manifest baselines and `queries` → composite DB index manifests so CI fails on wire-shape or index drift (`contract-artifact-stale`).
- **Dual-Write Parity & Immutability (`R2`–`R3`):** Route mirrored document/subcollection writes through one atomic batch DAO entrypoint, update or return the authoritative in-memory entity, and wrap test inputs in `deepFreeze(...)` to catch shared-reference mutation bugs.
- **UI Stale-Async Races & Re-Entrancy (`R3`):** Test search, pagination, and entity-switch components with delayed out-of-order responses (`req1` resolves after `req2`), asserting `AbortController` or monotonic generation guards prevent stale overwrites, double-click triggers are locked while loading, and entity-scoped subtrees reset via `key={entityId}`.
- **Composed-App Auth Matrix & Deploy Serving Readiness (`R2`–`R5`):** Execute every mounted route against `{ unauthenticated, disabled-user, lower-role, admin }` through the real composed router middleware stack (never mocking auth middleware), and verify scheduler OIDC audiences, required env vars, and bundle/CSS ceilings before deploy (`R5`).
- **Retry Budgets, Idempotency Keys & Blast-Radius Circuit Breakers (`R2`–`R4`):** Enforce remaining-deadline checks before every retry attempt, attach deterministic idempotency keys to external email/payment/webhook calls, negative-cache failing external lookups, and guard bulk delete/reconcile loops with explicit max-count / percentage circuit breakers.
- **Browser Layout Landmarks & Mobile E2E Stability (`R4`–`R7`):** Assert `<main>` landmark presence and `scrollWidth <= clientWidth` across responsive breakpoints in fast CDP/component checks, keep gzipped CSS/JS ceilings enforced in CI, and require `centerElement: true` + keyboard dismissal in mobile E2E flows.
