# Veristack (`vstack`)

**Stop shipping test theater and AI slop.**
Warning, veristack is "slop" :)

Veristack is a deterministic **9-rung zero-defect verification ladder (`R0 → R8`)**, cross-language static analyzer (`vstack`), native compiler/linter kit, runnable formal proof suite, and portable agent skill for **TypeScript, C#/.NET, Rust, and Python**.

> **Prime Directive:** Push every check as far **down** the ladder toward **R0** as possible without losing the failure mechanism. Faster CI, zero flake masking, fewer agent tokens, higher assurance.

---

## Why This Exists

AI-assisted codebases fail in two predictable ways:

1. **Test theater:** thousands of heavily mocked unit tests and brittle E2E scripts that mirror buggy code, pass when behavior breaks, and hide failures behind `retries: 3`, `|| true`, or `continue-on-error: true`.
2. **Defects by omission:** boolean flag soup admitting impossible states, wall-clock duration bugs, assertions silently stripped in release builds, accidental $O(N^2)$ loops, and unverified state machines.

Veristack turns zero-defect practices from **software engineering**, **Lean/Toyota manufacturing**, **silicon/ASIC verification**, and **safety-critical software** into fast, deterministic gates you can run locally and in CI.

---

## The 9-Rung Push-Down Ladder

```text
R0  Static Locks, Anti-Slop & Anti-Cheat          (< 2 s   | 100% files)  ← Push everything here first
R1  Types, Explicit State Machines & Structure    (1–10 s  | 100% files)
R2  Pure Logic, Data Tables, MC/DC & PBT          (10ms–2s | 15–40 specs)
R3  Stateful MBT, Cross-Coverage, Host & Twins    (0.2–5 s | 5–15 suites) ← Replaces ~80% of E2E
R4  Real Engines, Migrations, 1..N Faults & DST   (2–30 s  | 3–8 slices)  ← Never mock DB/broker below R4
R5  Formal Proofs, Mutation & 90/10 Circuits      (30s–15m | diff/nightly)
R6  Empirical Big-O, SPC Drift, RTY & Load        (2–30 m  | 1–2 / svc)
R7  Thin Golden-Path E2E & Hardware Proof         (2–15 m  | 5–15 MAX)
R8  Live Production Verification & Boot BIST      (Always  | 3–10 synthetics)
```

---

## 30-Second Quick Start

Requires [Bun](https://bun.sh) `>= 1.2.0`.

```bash
git clone https://github.com/a1ter-nate/veristack.git
cd veristack

# Self-verify Veristack (0 errors, 0 warnings, 0 cheats, 0 rung holes)
bun run check

# Scan any repo for rung holes, cheats, prose comments, implicit state machines & push-down wins
bun ./src/cli.ts scan /path/to/repo
bun ./src/cli.ts scan /path/to/repo --json   # For coding agents
bun ./src/cli.ts scan /path/to/repo --md     # For PR evidence
```

### High-Leverage CLI Gates (`vstack`)

```bash
# Static, ratchet & anti-cheat gates (TS/JS, C#, Rust, Python)
bun ./src/cli.ts no-comments /path/to/repo --fail
bun ./src/cli.ts state-machines /path/to/repo --fail
bun ./src/cli.ts diff-cheats /path/to/repo --base origin/main --fail
bun ./src/cli.ts scan /path/to/repo --ratchet .verification/ratchet.json

# Zero-defect engineering checks (V25 Formal Sync, V33 Red-Before-Fix, V34 MC/DC, V41 SPC, V42 Big-O)
bun ./src/cli.ts formal-sync /path/to/repo --fail
bun ./src/cli.ts red-before-fix /path/to/repo --base HEAD --test-cmd "bun test tests/bugfix.test.ts"
bun ./src/cli.ts mcdc "isAdmin || (isOwner && !isSuspended && hasScope)"
bun ./src/cli.ts spc ./metrics.json --fail
bun ./src/cli.ts big-o ./scaling.json --max-time-exp 1.35 --fail

# 90/10 BYO System 1 Circuits (providers: jev, laya, local, command, fixture)
bun ./src/cli.ts circuit list
bun ./src/cli.ts circuit run test-triage /path/to/repo --provider fixture
bun ./src/cli.ts circuit run pr-risk-router /path/to/repo --base HEAD --provider local --model qwen3.5:9b
bun ./src/cli.ts circuit run perf-architecture-advisor /path/to/repo --provider jev --endpoint "$JEV_API_URL"
```

---

## 4-Language Parity (Native Enforcement + Formal Proofs)

Every rule is language-agnostic, backed by native compiler/linter plugins and runnable `R0 → R5` proofs (including exhaustive formal model checks) in all 4 languages:

| Language | Native `R0`–`R1` Enforcement | Runnable `R0`–`R5` Proof | Guide |
| :--- | :--- | :--- | :--- |
| **TypeScript / JS** | [oxlint-no-comments.mjs](lint/oxlint-no-comments.mjs), [oxlint-explicit-state-machine.mjs](lint/oxlint-explicit-state-machine.mjs), strict `tsconfig` | `src/` + `tests/` ([formal-verification.test.ts](tests/formal-verification.test.ts)) | [typescript.md](skill/references/languages/typescript.md) |
| **C# / .NET 10** | Roslyn [VStack.Analyzers](lint/csharp/VStack.Analyzers/) (`VSTACK001`–`VSTACK004`), `TreatWarningsAsErrors` | [templates/csharp-reference/](templates/csharp-reference/) (BFS formal proof, `OrderLifecycle.dfy`, `FsCheck`, `Stryker.NET`) | [csharp.md](skill/references/languages/csharp.md) |
| **Rust (2024)** | `unsafe_code = "forbid"`, `warnings = "deny"`, Clippy `unwrap_used`/`expect_used`/`panic`/`wildcard_enum_match_arm = "deny"` | [templates/rust-reference/](templates/rust-reference/) (`stateright` BFS, `#[cfg(kani)]`, `proptest`, `cargo-mutants`) | [rust.md](skill/references/languages/rust.md) |
| **Python (3.12+)** | `ruff` (strict + prod `S101` assert ban), `mypy --strict` (`disallow_any_explicit`), `assert_never` | [templates/python-reference/](templates/python-reference/) (`hypothesis` PBT/MBT, BFS formal check + cross-coverage, `mutmut`) | [python.md](skill/references/languages/python.md) |

Universal protocol spec: [templates/formal/order_lifecycle.qnt](templates/formal/order_lifecycle.qnt) (Quint / typed TLA+).

---

## What `vstack` Catches Out of the Box

- **Zero-slop static locks:** `no-comments` (prose/excuse comments banned; `WARNING:`, `SAFETY:`, directives, and public docs allowed), `no-implicit-state-machine` (boolean soup, optional state bags, scattered mutations, non-exhaustive switches), escape hatches, swallowing catches, and unjustified suppressions.
- **Anti-cheat CI & test integrity:** `continue-on-error: true`, `|| true`, `--no-verify`, retries/skips, missing `timeout-minutes`/`concurrency`, `<NoWarn>`, blanket `#[allow]`, tautological/self-derived/multi-status asserts, fixed sleeps, coverage-farm files, and unexercised tests.
- **Brownfield ratchets & formal sync (`V07`, `V25`):** Packwerk-style auto-shrinking `--ratchet` baselines for day-1 legacy adoption and `vstack formal-sync` commit-drift checks so formal models never silently pass on changed code.
- **Cross-discipline zero-defect gates (`V30`–`V42`):** wall-clock duration CDC, unbounded loops, release-stripped prod asserts (`Debug.Assert` / `debug_assert!` / bare Python `assert`), `.verification/control-plan.json` FMEA & `REQ-*` traceability, `.verification/escapes.json` A3 repeat-defect Poka-Yoke ratchet, `red-before-fix`, `mcdc`, `spc`, `big-o`, and deterministic $O(N^2)$/N+1 perf-hygiene lints.
- **4 plug-and-play 90/10 System 1 circuits:** deterministic static facts resolve ~90% at $0; only ambiguous items invoke a BYO System 1 model under a formally verified 3-band confidence + contradiction-escalation policy (`test-triage`, `pr-risk-router`, `instruction-lint-promoter`, `perf-architecture-advisor`).

---

## Portable Agent Skill

Drop [skill/](skill/) into `~/.agents/skills/veristack` or `~/.claude/skills/veristack` (includes `SKILL.md`, `agents/openai.yaml`, and progressive-disclosure references) so coding agents run `vstack scan . --json` before designing or refactoring tests:

- [skill/SKILL.md](skill/SKILL.md) — Core 9-rung ladder, shared vocabulary, and 4-phase workflow
- [skill/references/01-test-and-verification-index.md](skill/references/01-test-and-verification-index.md) — All 42 mechanisms (`V01`–`V42`)
- [skill/references/02-linter-and-antislop-stack.md](skill/references/02-linter-and-antislop-stack.md) — `R0`–`R1` linter architecture & ratchets
- [skill/references/03-pushdown-protocol-and-budgets.md](skill/references/03-pushdown-protocol-and-budgets.md) — Routing matrix, budgets & CI speed
- [skill/references/05-formal-verification.md](skill/references/05-formal-verification.md) — Formal verification playbook (`R5 / V25`)
- [skill/references/06-system1-circuits.md](skill/references/06-system1-circuits.md) — 90/10 BYO System 1 circuit runtime
- [skill/references/07-zero-defect-cross-discipline.md](skill/references/07-zero-defect-cross-discipline.md) — Lean, Silicon & Safety-Critical verification

---

## Verify All 4 Languages Locally

```bash
bun run check        # TS/JS/Bun + skill integrity + vstack self-scan
bun run test:csharp  # Roslyn VStack.Analyzers + .NET 10 reference solution
bun run test:rust    # rustfmt + clippy -D warnings + proptest + stateright
bun run test:python  # ruff + mypy --strict + pytest + hypothesis + formal check
```

---

## Inspiration, Credits & Clean-Room Attribution

Veristack synthesizes ideas from public engineering literature, open-source tooling, and cross-discipline reliability research.

### Open-Source Projects (MIT / Apache-2.0)
- [`deterministic-machines/deslop-please`](https://github.com/deterministic-machines/deslop-please) *(MIT)* — deep-module structural anti-slop linting (`field-leak`, `shallow-module`, cycles, tangles).
- [`dmmulroy/anti-slop`](https://github.com/dmmulroy/anti-slop) *(MIT)* — strict TypeScript escape-hatch bans against low-evidence casts and `unknown` laundering.
- [`@interfere/landmines`](https://github.com/interfere-inc/landmines) *(MIT)* — static test-integrity rules that make the honest testing path the only one that lints.
- [`mattpocock/skills`](https://github.com/mattpocock/skills) *(MIT)* — deep-module seam vocabulary (`codebase-design`), vertical-slice TDD discipline, and agent-skill craft (`writing-for-agents`).
- [`cursor/plugins` (`pstack`)](https://github.com/cursor/plugins/tree/main/pstack) *(MIT)* — formal-spec sync-commit upkeep, 5-step blast-radius proof ladder, 7-question benchmark vetting, and repeat-correction promotion (`/correct`).
- [`antithesishq/bombadil`](https://github.com/antithesishq/bombadil) *(MIT)* — autonomous UI/TUI state-space exploration and `always`/`sometimes` reachability checks.
- [`tigerbeetle/tigerbeetle`](https://github.com/tigerbeetle/tigerbeetle) (`TIGER_STYLE.md`, *Apache-2.0*) — paired release-active assertions and deterministic simulation discipline.

### Articles, Papers & Cross-Discipline Literature
- **Matteo Vaccari — [*Tests as Data*](https://martinfowler.com/articles/tests-as-data.html)** — customer tests as the human-AI contract, declarative data tables, constrained test DSLs, and the file-change lock matrix.
- **John Ousterhout — *A Philosophy of Software Design*** — deep modules, narrow interfaces, and code locality.
- **Meta Engineering (Mark Harman, Matthew Becker et al.) — [*Just-in-Time Catching Test Generation at Meta* (`arXiv:2601.22832`)](https://arxiv.org/abs/2601.22832)** — diff-time catching tests without permanent regression-suite bloat.
- **TypeSafe AI (JEV)** — non-autoregressive, calibrated System 1 decision primitives composed with deterministic code.
- **Shopify Packwerk & C++26 Contracts (`P2900R14`)** — auto-shrinking baseline ratchets for day-1 brownfield adoption and per-invariant `ignore`/`observe`/`enforce` modes.
- **Lean, Silicon & Safety-Critical Classics** — Shigeo Shingo (*Zero Quality Control / Poka-Yoke*), Toyota Production System (*Jidoka*, *A3*), Walter Shewhart (*SPC / Nelson rules*), Genichi Taguchi (*orthogonal arrays*), Philip Crosby (*Rolled Throughput Yield*), NASA JPL (*Power of 10*), DO-178C (*MC/DC & bidirectional traceability*), SQLite (*TH3 & `1..N` fault sweeps*), and seL4 (*non-interference*).

*Clean-room notice: Veristack is an original, from-scratch MIT implementation. No third-party source code was copied from any project listed above; every referenced open-source repository is cited openly for the ideas, rules, and engineering principles it inspired. See [skill/references/04-source-patterns-digest.md](skill/references/04-source-patterns-digest.md) for the full traceability map.*

## License

[MIT](LICENSE) © 2026 [a1ter-nate](https://github.com/a1ter-nate)
