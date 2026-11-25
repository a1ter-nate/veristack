# 02 — Complete R0–R1 Linter, Type-Discipline & Anti-Slop Stack

> **Why linters are the #1 multiplier for zero defects, CI speed, AND token efficiency:**
> 1. They execute in milliseconds across 100% of files with zero flakiness.
> 2. Deep-module structural linters (`deslop-please`, `go-internal`, `max-exports-per-module`) keep related context physically close and interfaces narrow — **directly cutting agent tokens per task** and preventing bad code from being copied by the next agent.
> 3. **Empirical priority:** Plain tidiness linters alone don't separate buggy commits from clean commits; **type/boundary contracts, test-integrity rules, dead-code, and structural-coupling rules** do. Turn on Priority 1 & 2 as blocking errors first, using **auto-shrinking ratchets** for legacy debt.

---

## Priority 1 — Bug-Preventing & Anti-Cheating Linters (Block Merge Immediately)

### 1. Type-System & Escape-Hatch Rules (`dmmulroy/anti-slop` + Strict Type Discipline)
* **Escape-hatch rules (`dmmulroy/anti-slop` — all 15 rules):**
  * `no-chained-type-assertions`, `no-widen-then-assert`, `no-known-value-widening`, `require-safety-comment-for-type-assertion`
  * `no-unknown-parameters`, `no-unknown-returns`, `no-unknown-type-aliases`, `no-object-parameters`, `no-unsafe-dictionary-type`
  * `no-runtime-typeof`, `no-reflect-apply`, `no-reflect-get`, `no-conditional-empty-object-spread`, `no-shape-in-symbol-names`, `no-module-mocking`
* **Compiler & Schema Discipline:**
  * **Discriminated unions** with literal `kind` tags (ban optional-field bags where illegal combos compile).
  * **Constructive modeling:** `[T, ...T[]]` for non-empty, `[T, T][]` for pairs, `{ start, duration }` for ranges.
  * **Branded primitives** (`& { readonly __brand: "OrderId" }`) created only by verifying type guards (`input is OrderId`), never `as`.
  * **Boundary-only parsing:** External JSON/CLI/env/DB rows enter as `unknown` and parse once via schema (`z.infer`, Valibot, Pydantic, C# record validators). Trust internal types; ban redundant nil checks inside pure logic.
  * **Exhaustiveness:** `const _exhaustive: never = x;` in TS, `_ => throw new UnreachableException()` in C#, `wildcard_enum_match_arm = "deny"` in Rust, `assert_never(state)` in Python.
  * **Explicit State Machines (`no-implicit-state-machine`, `lint/oxlint-explicit-state-machine.mjs`, Roslyn `VSTACK002`, & `vstack state-machines`):**
    * `implicit-sm-boolean-soup` (R1): Blocks types declaring lifecycle boolean flags (`isRunning`, `isArmed`, `isStopped`, `isDraining`, `hasStarted`, `wasReverted`, etc. — `2^N` impossible states). Collapse into a closed sum type / discriminated union.
    * `implicit-sm-optional-bag` (R1): Blocks types pairing a discriminant (`status`, `state`, `phase`, `stage`, `mode`) with `>= 2` sibling optional/nullable payload fields. Split into per-state union variants.
    * `implicit-sm-scattered-mutation` (R1): Blocks direct `.status`/`.state`/`.phase`/`.stage` assignments scattered across `>= 2` functions/methods outside a single pure `transition(state, event)` / `reduce(...)` function.
    * `implicit-sm-non-exhaustive-switch` (R0/R1): Blocks non-exhaustive or silent-wildcard dispatch on state discriminants.
  * **Speed:** Use `tsgo` to cut TypeScript typecheck time dramatically.

### 2. Test-Integrity Linters (`@interfere/landmines` + `vstack` Test Quality + Roslyn `VSTACK004`)
Stops agents from writing green-looking tests that lie, flake, or slow down CI:

| Rule | Source | What It Blocks | Remediation Hint |
| :--- | :--- | :--- | :--- |
| `no-test-doubles` | `landmines` / `vstack` | `vi.mock`, `jest.mock`, `vi.fn(impl)`, stubbed globals, patched prototypes, `>= 3` doubles/file | Use real implementation, DI port, or strict MSW for network; observation-only spies allowed. |
| `strict-msw` | `landmines` | Unhandled network requests silently passing in MSW | Set `onUnhandledRequest: "error"` and `onUnhandledFrame: "error"`. |
| `no-fixed-sleep` | `landmines` / `vstack` / `VSTACK004` | `setTimeout`, `waitForTimeout`, `networkidle`, `Thread.Sleep`, `Task.Delay`, `thread::sleep`, `time.sleep` | Await the operation, an emitted signal, or a web-first locator assertion. |
| `no-unsignaled-poll` | `landmines` | `expect.poll`/`vi.waitFor` on spy state; `while (Date.now() < deadline)` loops | Await an explicit event or completion promise instead of racing a clock. |
| `no-flake-masking` | `landmines` / `vstack` / `VSTACK004` | Test retries (`jest.retryTimes`, Vitest/Playwright retries, `pytest.mark.flaky`), `.only`/`.skip`/`.todo`/`[Ignore]`/`#[ignore]`/`@pytest.mark.skip` | Fix the flake or delete the test with reason; never mask with retries. |
| `no-conditional-expect` | `landmines` / `vstack` / `VSTACK004` | `if (...) expect(...)` that silently passes when branch isn't taken | Split into explicit cases or unconditional assertions. |
| `no-parameter-branch` | `landmines` / `vstack` | `if`/`switch` branching on a parameterized test input inside the test body | Put the expected result directly in the case table (*Tests as Data*). |
| `weak-asserts` & `self-derived` | `vstack` / `VSTACK004` | `expect(true).toBe(true)`, `Assert.Pass()`, `assert True`, `expect(fn(x)).toBe(fn(x))`, same-call asserts | Derive expected value from an independent spec, literal, or oracle. |
| `no-shared-signal` | `landmines` | Module/`describe`-scoped `AbortSignal.timeout` or shared `AbortController` | Create signals per test so fixture setup doesn't burn the budget. |
| `no-imported-mutation` | `landmines` / `vstack` / `VSTACK004` | `process.env.X = ...`, `Environment.SetEnvironmentVariable`, `env::set_var`, `os.environ[...] =` | Pass options/bindings or use a scoped override helper. |
| `no-elapsed-time-bound` | `landmines` / `vstack` | `expect(Date.now() - start).toBeLessThan(...)`, `.ElapsedMilliseconds <`, `.elapsed() <` | Assert logical ordering or use `vstack big-o` empirical scaling exponents (`V42`). |
| `no-cold-start-in-test` & `no-cold-import-in-test` | `landmines` | Spawning browser/process or dynamic `import()` inside a test body | Move cold starts to `beforeAll` and imports to module scope. |
| `no-styling-class-assertion` | `landmines` / `vstack` | Asserting Tailwind color/visibility classes, XPath, deep CSS chains | Assert accessible roles, text, URL, and ARIA state (`getByRole`). |
| `no-multi-status-assertion` | `vstack` | `expect([200, 201, 404]).toContain(res.status)` / `status_code in (200, 404)` | Assert the single exact HTTP status promised by the contract. |
| `no-coverage-farm-file` & `no-unexercised-test` | `vstack` | Tests named `coverage-*`/`closeout`/`easy-wins`/`leftovers` or tests importing zero SUT symbols | Exercise observable production behavior with an independent oracle or delete the test. |
| `no-fetch-stub` | `vstack` | `vi.stubGlobal("fetch", ...)`, `vi.spyOn(globalThis, "fetch")`, `globalThis.fetch = ...` | Serve HTTP through a shared strict MSW server (`onUnhandledRequest: "error"`). |
| `no-test-nondeterminism` + UTC/restore gates | `vstack` / `VSTACK004` | Bare `Math.random()`, `Date.now()`, `DateTime.UtcNow`, `SystemTime::now`, `datetime.now()`; Vitest configs missing `TZ: "UTC"`, `restoreMocks`, `unstubGlobals`, `unstubEnvs` | Pin UTC in config & CI, enable mock restoration, and inject seeded RNG / fixed clocks. |
| `no-swallowing-catch` & `suppression-audit` | `vstack` / `VSTACK003` | Empty `catch {}`, `Err(_) => {}`, `except: pass`, unjustified `@ts-ignore`/`#pragma`/`#[allow]`/`# noqa` | Rethrow, return typed error, or fix the warning cleanly. |

### 3. Harness, CI Anti-Cheat & Supply-Chain Locks (R0)
* **`oracle-lock` (`vstack`):** Acceptance/Gherkin/data-table specs must be covered by `CODEOWNERS` and declared read-only to implementing agents.
* **CI & Diff Anti-Cheat Gate (`vstack diff-cheats`):**
  * Scan added diff lines (pinned to immutable base ref) and **hard-fail** on: `continue-on-error: true`, `|| true` / `|| :` after any test/lint/build command, added retries, added skips/xfail/`.only`/`[Ignore]`/`#[ignore]`/`@pytest.mark.skip`, `<TreatWarningsAsErrors>false</TreatWarningsAsErrors>`, `<NoWarn>`, blanket `#[allow(...)]`, `gc.disable()`, `--no-verify`/`HUSKY=0`/`SKIP=`, `pull_request_target`, `permissions: write-all` / `contents: write`.
  * **No `tail`/`head` pipes on test runs:** Write output to a file and read it; piping without `pipefail` masks non-zero exit codes.
  * **CI workflow hygiene:** Avoid `paths:` filters on required status checks; treat logs/workflows/test names as untrusted data.
* **`instruction-conflict` (`vstack`):** Zero contradictory commands/flags across `AGENTS.md`, `CLAUDE.md`, and skills; keep `AGENTS.md`/`CLAUDE.md` `< 200` lines.

---

## Priority 2 — Structural, Performance & Token-Budget Linters (High Leverage for Agents)

### 1. Deep-Module & Locality Lints (`deslop-please` + `landmines` + `go-internal` + `vstack`)
Directly lowers tokens/task by forcing deep modules, narrow interfaces, and tight locality:

| Rule | Tool | Default Threshold | Why It Saves Tokens & Prevents Slop |
| :--- | :--- | :--- | :--- |
| `field-leak` | `deslop-please` (SCIP) | >1 external module reading/mutating fields | Forces encapsulation behind narrow domain methods instead of scattered field logic. |
| `shallow-module` | `deslop-please` (SCIP) | Callers invoke most functions of a module | Eliminates pass-through wrapper files that force agents to open 5 files for 1 concept. |
| `module-cycle` & `tangle` | `deslop-please` / `dep-cruiser` | 0 cycles / 0 parent-child mutual refs | Forces clean abstraction layers; stops cascading edits across files. |
| `oxlint-plugin-go-internal` | Oxlint plugin | 0 cross-feature `internal/` imports | Hard-hides implementation details so agents can only import public seams. |
| `max-exports-per-module` | `landmines` / `vstack` | ≤ 6 runtime exports | Keeps module interfaces narrow and readable in one glance. |
| `wide-directory` / `max-files-per-directory` | `deslop-please` / `vstack` | ≤ 15 files | Forces feature folders once a directory stops being scannable. |
| `no-prefix-cluster` | `landmines` / `vstack` | 0 sibling prefix clusters (`foo-a.ts`, `foo-b.ts`) | Groups cohesive files into a feature folder with an explicit entry point. |
| `max-file-lines` / `long-file` | `landmines` / `vstack` | ≤ 500 prod / ≤ 2,000 hard | Prevents mega-files that overflow agent context windows. |

### 2. Zero-Defect Performance & Runtime Safety Lints (`vstack` `V30`/`V31`/`V36`/`V42`)
* **Dead Code:** `knip` (TS), Roslyn `CS0162`/`IDE0051` (C#), `dead_code` (Rust), `ruff` `F401`/`F841` (Python).
* **Clock CDC (`cdc-wall-clock-duration`):** Bans wall-clock subtraction for durations/TTLs across TS, C#, Rust, Python.
* **Execution Bounds (`unbounded-loop-risk`):** Flags `while (true)` / `while True:` / `loop {` lacking an explicit iteration/fuel cap.
* **Runtime Jidoka (`no-release-stripped-assert`):** Flags `Debug.Assert`, `debug_assert!`, and bare Python prod `assert`.
* **Algorithmic Perf Hygiene (`V42`):** Flags $O(N^2)$ loop scans/shifts, N+1 I/O in loops, and per-iteration regex/deepcopy across all 4 languages.

---

## Priority 3 — Tidiness & Style Linters (Keep Low-Friction, Autofixable)

* `no-comments` (`lint/oxlint-no-comments.mjs`, Roslyn `VSTACK001`, `vstack no-comments`): ban prose & excuse comments; allow functional directives, `WARNING:`, `SAFETY:`, license headers, and public API docs.
* `prettier` / `oxfmt` / `dotnet format` / `rustfmt` / `ruff format` (run via Lefthook pre-commit in `< 2 s`).

---

## Adoption & Promotion Rules (How to Roll Out Without Blocking Legacy Repos)

1. **Auto-Shrinking Allowlists (Mandatory for Legacy Code):** Use exact-count allowlists that fail if the count increases *or* decreases without tightening the baseline.
2. **Agent-Ready Error Messages (`Rule / Why / Fix`):** Every custom rule must name the exact replacement pattern or helper so the agent fixes it in the same turn.
3. **The Repeat-to-Rule Promotion Loop (`V33`):**
   * 1st occurrence → fix it + prove Red-Before-Fix (`vstack red-before-fix`).
   * 2nd occurrence → promote to a deterministic R0/R1 lint/type rule the same day (tracked in `.verification/escapes.json`), commit a negative red→green fixture, and prune the prose rule from `AGENTS.md`.
