---
name: veristack
description: "Verification ladder, push-down, and anti-slop review gates (`vstack`). Use when designing feature checks, pushing slow or bloated tests down to R0–R3, locking down an escaped bug, or building a stakes-ranked PR review brief."
---

# Veristack

Place every check on the lowest rung (`R0`–`R8`) that preserves its exact failure mechanism, prefer **subtraction** over additive workarounds, and reserve human attention for the highest-**stakes** decisions.

## Leading Vocabulary

Use these tokens consistently across plans, PR briefs, and reviews:

- **Rung (`R0`–`R8`)**: verification tier ordered by speed and determinism.
- **Push-down**: moving a check to a lower rung while preserving the exact failure mechanism.
- **Seam**: the public boundary where callers and checks observe behavior.
- **Oracle**: an independent source of truth (spec, literal, table, reference model) that disagrees with broken code.
- **Tight**: fast (seconds), deterministic, and single-command repeatable.
- **Red**: binary observable failure on the target defect before fixing (`vstack red-before-fix`).
- **Two-Edit Test**: break behavior → check goes **red**; refactor internals preserving behavior → check stays green.
- **Jidoka**: release-active production invariants that fail closed on the first corrupt unit.
- **Subtraction**: deleting or simplifying code, wrappers, or redundant tests before adding new ones.
- **Stakes**: blast radius that determines which plan, contract, or diff slice requires direct human judgment.
- **Gardener Protocol (`uncomplect`)**: every new lint rule or static fence must be proven with a planted fault (**red** → green) before trusting it in CI.
- **No fence yet**: explicit gap honesty — name every un-fenced approximation or soundiness site verbatim (`No fence yet: ...`) instead of pretending static analysis covers it.

## The 9-Rung Ladder

| Rung | Layer | Speed | Primary Job |
| :---: | :--- | :--- | :--- |
| **R0** | Static, Anti-Slop & Locks | `< 2 s` | Format, `no-comments`, escape-hatch bans, test integrity, anti-cheat diff, agent-doc hygiene |
| **R1** | Types, State Machines & Structure | `1–10 s` | Strict compiler, closed sum-type state machines, deep modules, CDC/bounds, FMEA plan |
| **R2** | Pure Logic, Tables & Oracles | `10 ms–2 s` | Tests-as-Data tables, MC/DC tables, stateless PBT, differential oracles |
| **R3** | Stateful MBT, Host, UI & Twins | `0.2–5 s` | Primary E2E replacement (~80%): Stateful MBT, cross-coverage, in-process host, wire contracts, strict twins |
| **R4** | Real Engines, Faults & DST | `2–30 s` | Real DB/migrations, real broker DLQ, `1..N` fault/torn-write sweeps, seeded DST |
| **R5** | Formal, Mutation, Fuzz & Circuits | `30 s–15 m` | Model checks (`Bend 2`/`Quint`/`Stateright`/`Kani`/`Dafny`/`Z3`), diff mutation, fuzzing, `vstack circuit` |
| **R6** | Big-O, SPC, RTY & Load | `2–30 m` | Scaling exponents (`vstack big-o`), SPC drift (`vstack spc`), Rolled Throughput Yield, load/soak |
| **R7** | Thin Golden-Path E2E & Hardware | `2–15 m` | 5–15 real end-to-end journeys max; separate physical hardware proof from simulation |
| **R8** | Live Production & Boot BIST | Continuous | `< 500 ms` fail-closed Boot BIST, 3–10 synthetics, canary/shadow verification, tail-sampled telemetry |

## Workflow (Execute in Order)

### Phase 0: Measure Ground Truth & Bootstrap Rungs

1. Read the relevant source files, existing checks, and prior art directly before generating code.
2. On a greenfield or unconfigured repo without `.verification/rungs.json`, run `vstack init .` to scaffold `.verification/rungs.json` and fail-closed agent hooks (`PreToolUse`, `PostToolUse`, `Stop`).
3. Run `vstack scan . --json` (pair with `--ratchet .verification/ratchet.json` on brownfield repos; run `vstack --help` for subcommands).

- **Done when:** `.verification/rungs.json` declares every applicable rung, rung coverage, push-down candidates, and findings are in hand, and every active `cheat`, `no-comments`, `no-implicit-state-machine`, `agent-doc-stale-path`, and `formal-spec-stale` error is cleared (or tracked on a shrink-only ratchet). Never stop on a repo with zero tests or uncovered applicable rungs — author real tests across `R2`+ (per archetype) before concluding.

### Phase 1: Agree Seams, Subtraction & Minimum Valid Rung

For every requirement, bugfix, or check above `R2`:

1. State the failure mechanism in one sentence (*what wrong outcome, and what minimum boundary is required for it to exist?*).
2. Check **subtraction** first: name any existing wrapper, workaround, prose rule, or duplicate test that can be deleted or folded into a deeper module.
3. Walk the 4 gates and stop at the first **YES**:
   - **Q1 (`R0`/`R1`):** Can a deep module, closed sum type, strict compiler flag, or custom lint (`Rule / Why / Fix`) block the defect statically? Build the static lock with a **red**→green fixture and delete the runtime test.
   - **Q2 (`R2`):** Pure calculation, validation, parsing, or transition matrix? Extract a pure **seam** and write one declarative Tests-as-Data table or PBT.
   - **Q3 (`R3`):** Multi-step interleavings → Stateful MBT + cross-coverage. HTTP routing/auth → In-process Host. Wire shape → Contract + strict Twin. UI states/a11y → Component UI + strict network interceptor.
   - **Q4 (`R4`–`R7`):** Real SQL/migrations/bus DLQ → real `R4` engine. Distributed races/crashes → `R4` DST or `R5` formal model. Real OAuth/CORS/webhooks/hardware → `R7` (within the 5–15 cap).
4. Match dependency seams: absorb in-process helpers into deep modules; keep local stand-ins internal; define Ports & Adapters for remote owned services; inject typed SDK ports backed by strict twins for external vendors.

- **Done when:** every target seam lists `(a) failure mechanism`, `(b) subtraction/simplification`, `(c) minimum valid rung`, and `(d) residual blind spot`, confirmed with the user before writing tests for a new feature.

### Phase 2: Author & Lock the Oracle

1. Express matrices as declarative `.json`/`.csv`/`.yaml` tables and compound security/billing guards as MC/DC tables (`vstack mcdc`).
2. Derive expected outputs from independent specs, literals, or reference models.
3. Apply positive boundary patterns:
   - Run SQL, migrations, and broker DLQ checks at `R4` against real engines.
   - Model lifecycle state as a closed sum type with one pure `transition(state, event)` boundary and exhaustive dispatch.
   - Keep production invariants release-active (`Jidoka`: `InvariantViolationError` / checked `if (!ok) throw`).
   - Use Design for Testability (injectable clocks, RNGs, storage ports, domain telemetry, `< 500 ms` Boot BIST).
   - Await explicit signals or web-first locators so every failure fails loudly.
   - Dispatch a **fresh-context subagent** (IV&V) to audit implementation against the locked spec on high-**stakes** surfaces.

- **Done when:** every new or moved check has one primary owner at its strongest seam, passes the Two-Edit Test, and leaves locked oracle files untouched during pure refactors.

### Phase 3: Prove Red → Green, Prune & Brief the Human

1. For bugfixes, prove **red**→green with `vstack red-before-fix . --base <ref> --test-cmd "<cmd>"`. Record repeat defect classes (`>= 2×`) in `.verification/escapes.json` and promote them to `R0`/`R1`.
2. For new checks or push-downs, inject one controlled fault (or run diff mutation) to confirm **red**, restore, and confirm green.
3. Run `vstack verify . --strict` and `vstack doctor . --fail` (or `vstack scan . --ratchet .verification/ratchet.json` on brownfield repos tracking legacy debt; plus `vstack formal-sync . --fail` when formal models cover touched code) and delete redundant higher-rung tests replaced by tighter checks.
4. Run `vstack review-brief . --base <ref> --md` to check slop-asymmetry budgets and emit the **stakes**-ranked human review queue, verifier blind spots, and AI-authorship disclosure (remembering linters and agent reviews are necessary, never sufficient).
5. Emit one compact evidence line per moved/added check: `[ID | Old → New Rung | Failure Mechanism | Controlled-Fault Result | Residual Gap]`.

- **Done when:** `vstack verify . --strict` and `vstack doctor . --fail` exit `0` with zero uncovered rungs, zero zero-test repos, zero cheats/prose-comments/implicit-state-machines, controlled-fault **red**→green is recorded, redundant tests are deleted, and the human reviewer receives a bounded, **stakes**-ranked brief.

## Reporting False Positives or Tool Bugs Upstream

1. **Never** leak proprietary client code, internal paths, customer names, or secrets in bug/FP reports.
2. Run `vstack report --rule <id> --file <path:line> --anonymize --reason "<why>"` to preview a redacted, anonymized report (or append `--local` during offline/multi-repo sweeps to queue into `.verification/tool-feedback.jsonl` with zero network calls).
3. Inspect the scrubbed preview (or roll up queued entries via `vstack report --flush`), then file via `--submit` (when `gh` is available & approved) or `--url` (or clear the queue explicitly with `--flush --clear`).

## Disclosed References (Load Only the Active Branch)

Load **only** the language guide for the active repository:

| Active Language | Guide |
| :--- | :--- |
| TypeScript / JavaScript | [references/languages/typescript.md](references/languages/typescript.md) |
| C# / .NET | [references/languages/csharp.md](references/languages/csharp.md) |
| Rust | [references/languages/rust.md](references/languages/rust.md) |
| Python (3.12+) | [references/languages/python.md](references/languages/python.md) |

Load **only** the reference matching the current branch:

| Trigger Branch | Reference |
| :--- | :--- |
| Picking among all 42 verification mechanisms (`V01`–`V42`) and their blind spots | [references/01-test-and-verification-index.md](references/01-test-and-verification-index.md) |
| Configuring `R0`–`R1` anti-slop, test-integrity, structural, or custom lint rules | [references/02-linter-and-antislop-stack.md](references/02-linter-and-antislop-stack.md) |
| Routing a failure mechanism, sizing test counts, cutting CI time, or running an audit/push-down | [references/03-pushdown-protocol-and-budgets.md](references/03-pushdown-protocol-and-budgets.md) |
| Checking engineering lineage, manifesto principles, or public citations | [references/04-source-patterns-digest.md](references/04-source-patterns-digest.md) |
| Authoring a `Bend 2` / `Quint` / `TLA+` / `Stateright` / `Kani` / `Dafny` / `Z3` formal check (`R5`) | [references/05-formal-verification.md](references/05-formal-verification.md) |
| Running or wiring 90/10 BYO System 1 circuits (`vstack circuit`) | [references/06-system1-circuits.md](references/06-system1-circuits.md) |
| Applying Lean, Silicon, Safety-Critical, or Empirical Big-O practices (`V30`–`V42`) | [references/07-zero-defect-cross-discipline.md](references/07-zero-defect-cross-discipline.md) |
