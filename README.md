# Veristack (`vstack`)

**Zero-defect software verification across 9 rungs (`R0 → R8`), 42 mechanisms (`V01 → V42`), and 4 first-class languages (TypeScript, C#/.NET, Rust, Python).**

> **Prime Directive:** Push every check as far **down** the verification ladder toward **R0** (faster, smaller, more deterministic) as possible **without losing the failure mechanism**. Maximize module depth and static/compiler enforcement so **CI runtime**, **flake rate**, and **AI coding-agent token burn** stay minimal.

---

## Why Veristack?

Modern codebases — especially AI-assisted ones — drown in two opposite failure modes:
1. **Test bloat & theater:** thousands of heavily mocked unit tests and flaky E2E scripts that mirror buggy implementation code, pass when behavior breaks, and hide regressions behind `retries: 3`, `|| true`, or `continue-on-error: true`.
2. **Defects by omission:** illegal state combinations modeled as boolean flag soup, wall-clock duration bugs, release-stripped assertions, silent $O(N^2)$ regressions, and missing formal/property checks on critical state machines.

**Veristack** combines lessons from **software verification**, **Lean/Toyota zero-defect manufacturing** (Poka-Yoke, Jidoka, SPC, FMEA Control Plans, A3 Red-Before-Fix), **silicon/ASIC verification** (CDC, SVA, functional cross-coverage, LEC, PVT/HALT, Boot BIST), and **safety-critical software** (NASA JPL Power of 10, DO-178C MC/DC, SQLite fault sweeps, seL4 non-interference) into one deterministic CLI (`vstack`), native compiler/linter plugins, runnable reference proofs, and a portable agent skill.

---

## The 9-Rung Push-Down Ladder (`R0 → R8`)

```text
R0  Instant Static, Anti-Slop & Anti-Cheat Locks   (< 2 s   | 100% files)  ← Push everything here first
R1  Types, Explicit State Machines & Structure     (1–10 s  | 100% files)
R2  Pure Logic, Data Tables, MC/DC & Stateless PBT (10ms–2s | 15–40 specs)
R3  Stateful MBT, Cross-Coverage, Host & Twins     (0.2–5 s | 5–15 suites) ← #1 E2E replacement (~80%)
R4  Real Engines, Migrations, 1..N Faults & DST    (2–30 s  | 3–8 slices)  ← Never mock DB/storage below R4
R5  Formal Verification, Mutation & 90/10 Circuits (30s–15m | diff/nightly)
R6  Empirical Big-O, SPC Drift, RTY & HALT Cliffs  (2–30 m  | 1–2 / svc)
R7  Thin Golden-Path E2E & Hardware Proof          (2–15 m  | 5–15 journeys MAX)
R8  Live Production Verification & Boot BIST       (Always  | 3–10 synthetics)
```

---

## 30-Second Quick Start

Requires [Bun](https://bun.sh) `>= 1.2.0`.

```bash
git clone https://github.com/a1ter-nate/veristack.git
cd veristack

# Verify Veristack itself (0 errors, 0 warnings, 0 cheats, 0 rung holes)
bun run check

# Scan any repository for 9-rung gaps, anti-cheat violations, prose comments & push-down wins
bun ./src/cli.ts scan /path/to/repo
bun ./src/cli.ts scan /path/to/repo --json   # Machine-readable JSON for coding agents
bun ./src/cli.ts scan /path/to/repo --md     # Markdown PR evidence report
```

### Core CLI Commands (`vstack`)

```bash
# Static & anti-cheat gates (TS/JS, C#, Rust, Python)
bun ./src/cli.ts no-comments /path/to/repo --fail
bun ./src/cli.ts state-machines /path/to/repo --fail
bun ./src/cli.ts diff-cheats /path/to/repo --base HEAD --fail

# Zero-defect engineering gates (V33 Red-Before-Fix, V34 MC/DC, V41 SPC, V42 Empirical Big-O)
bun ./src/cli.ts red-before-fix /path/to/repo --base HEAD --test-cmd "bun test tests/bugfix.test.ts"
bun ./src/cli.ts mcdc "isAdmin || (isOwner && !isSuspended && hasScope)"
bun ./src/cli.ts spc ./metrics.json --fail
bun ./src/cli.ts big-o ./scaling.json --max-time-exp 1.35 --fail

# Plug-and-play 90/10 System 1 Circuits (BYO model: jev, laya, local, command, fixture)
bun ./src/cli.ts circuit list
bun ./src/cli.ts circuit run test-triage /path/to/repo --provider fixture
bun ./src/cli.ts circuit run pr-risk-router /path/to/repo --base HEAD --provider local --model qwen3.5:9b
bun ./src/cli.ts circuit run instruction-lint-promoter /path/to/repo --provider jev --endpoint "$JEV_API_URL"
bun ./src/cli.ts circuit run perf-architecture-advisor /path/to/repo --provider command --command "./my-s1-adapter"
```

---

## Full 4-Language Parity (Universal Principles → Native Enforcement)

Every principle in [skill/SKILL.md](skill/SKILL.md) is **language-agnostic**, backed by native compiler/linter plugins and runnable R0–R5 proofs (including exhaustive formal model checks) in all four languages:

| Language | Native R0–R1 Enforcement | Runnable R0–R5 Proof (with Formal Model Check) | Language Guide |
| :--- | :--- | :--- | :--- |
| **TypeScript / JS** | [oxlint-no-comments.mjs](lint/oxlint-no-comments.mjs), [oxlint-explicit-state-machine.mjs](lint/oxlint-explicit-state-machine.mjs), strict `tsconfig` | `src/` + `tests/` ([formal-verification.test.ts](tests/formal-verification.test.ts)) | [typescript.md](skill/references/languages/typescript.md) |
| **C# / .NET 10** | Roslyn [VStack.Analyzers](lint/csharp/VStack.Analyzers/) (`VSTACK001`–`VSTACK004`), `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` | [templates/csharp-reference/](templates/csharp-reference/) (`OrderFormalProofTests.cs`, `OrderLifecycle.dfy`, `FsCheck` PBT/MBT, `Stryker.NET`) | [csharp.md](skill/references/languages/csharp.md) |
| **Rust (2024)** | `[lints.rust]` (`unsafe_code = "forbid"`, `warnings = "deny"`), `[lints.clippy]` (`all`, `unwrap_used`, `expect_used`, `panic`, `wildcard_enum_match_arm` = `"deny"`) | [templates/rust-reference/](templates/rust-reference/) (`stateright` BFS model checker, `#[cfg(kani)]` harnesses, `proptest` PBT/MBT, `cargo-mutants`) | [rust.md](skill/references/languages/rust.md) |
| **Python (3.12+)** | `ruff` (strict rules + prod `S101` assert ban), `mypy --strict` (`disallow_any_explicit = true`), `assert_never` | [templates/python-reference/](templates/python-reference/) (`hypothesis` PBT + `RuleBasedStateMachine` MBT, exhaustive BFS + cross-coverage, `mutmut`) | [python.md](skill/references/languages/python.md) |

Universal protocol spec: [templates/formal/order_lifecycle.qnt](templates/formal/order_lifecycle.qnt) (Quint / typed TLA+).

---

## Built-In Static Guardrails & 90/10 Circuits

### Deterministic Static Rules (Zero Model Cost)
- **`no-comments`:** Bans prose/excuse comments across TS/JS, C#, Rust, and Python while allowing `WARNING:`, `SAFETY:`, license headers, tool directives, and public API docs.
- **`no-implicit-state-machine`:** Blocks all 4 implicit state-machine patterns (boolean-flag soup, optional/nullable state bags, scattered direct state mutations, and non-exhaustive or silent-wildcard dispatch).
- **Zero-Defect Cross-Discipline Rules (`V30`–`V42`):**
  - `cdc-wall-clock-duration` (bans wall-clock subtraction in durations/TTLs across all 4 languages)
  - `unbounded-loop-risk` (flags `while (true)` / `while True:` / `loop {` without visible iteration/fuel bounds)
  - `no-release-stripped-assert` (flags `Debug.Assert`, `debug_assert!`, and bare Python prod `assert`)
  - `.verification/control-plan.json` FMEA Control Plan & bidirectional `REQ-*` traceability gate
  - `.verification/escapes.json` A3 repeat-defect Poka-Yoke ratchet (`>= 2` occurrences require a linked R0/R1 check)
  - `perf-quadratic-loop-scan`, `perf-nplus1-io-in-loop`, `perf-loop-compile-or-deepcopy`, and `perf-anti-cheat`
- **CI & Test Anti-Cheat:** Blocks `continue-on-error: true`, `|| true` after check tools, `--no-verify`, retries/flake masking, `.only`/`.skip`/`[Ignore]`/`#[ignore]`/`@pytest.mark.skip`, `<NoWarn>`, blanket `#[allow(...)]`, tautological/self-derived/multi-status assertions, fixed sleeps, and unexercised tests.

### Plug-and-Play 90/10 System 1 Circuits (`vstack circuit`)
Deterministic code resolves ~90% of inputs at $0 via verified static facts and hard short-circuits; only ambiguous items invoke a pluggable **BYO System 1 decision model** (`jev`, `laya`, `local` OpenAI-compat, `command` executable, `fixture`, or custom JS engine) under a formally verified 3-band confidence + static-fact corroboration policy:
1. **`test-triage`** — Behavioral value & push-down classification for ambiguous test files.
2. **`pr-risk-router`** — Diff blast-radius & cheat-gated review tier routing.
3. **`instruction-lint-promoter`** — Identifies mechanical rules in `AGENTS.md`/`SKILL.md` ready for AST/compiler promotion.
4. **`perf-architecture-advisor`** — Routes verified complexity hotspots into optimization families (`algorithmic_complexity`, `data_layout_locality`, `batch_or_index_io`, `bounded_memory_streaming`).

---

## Portable Agent Skill Home

Install `skill/` into your agent's skill directory (e.g., `~/.agents/skills/veristack` or `~/.claude/skills/veristack`) so coding agents run `vstack scan . --json` before designing or refactoring tests:

- [skill/SKILL.md](skill/SKILL.md) — Universal principles, 9-rung stack, and 4-gate push-down protocol
- [skill/references/01-test-and-verification-index.md](skill/references/01-test-and-verification-index.md) — Complete 42-mechanism catalog (`V01`–`V42`)
- [skill/references/02-linter-and-antislop-stack.md](skill/references/02-linter-and-antislop-stack.md) — R0–R1 linter architecture & custom lint anatomy
- [skill/references/03-pushdown-protocol-and-budgets.md](skill/references/03-pushdown-protocol-and-budgets.md) — Failure-mechanism routing & sizing formulas
- [skill/references/04-source-patterns-digest.md](skill/references/04-source-patterns-digest.md) — Engineering lineage & citations
- [skill/references/05-formal-verification.md](skill/references/05-formal-verification.md) — Universal & per-language formal verification playbook
- [skill/references/06-system1-circuits.md](skill/references/06-system1-circuits.md) — 90/10 BYO System 1 circuit runtime & defaults
- [skill/references/07-zero-defect-cross-discipline.md](skill/references/07-zero-defect-cross-discipline.md) — Lean, Silicon & Safety-Critical verification practices

---

## Verify All 4 Languages Locally

```bash
bun run check        # TS/JS/Bun + vstack self-scan (0 errors, 0 warnings, 0 holes)
bun run test:csharp  # Roslyn VStack.Analyzers + .NET 10 reference solution
bun run test:rust    # rustfmt + clippy -D warnings + proptest + stateright formal check
bun run test:python  # ruff + mypy --strict + pytest + hypothesis + formal check
```

## License

[MIT](LICENSE) © 2026 [a1ter-nate](https://github.com/a1ter-nate)
