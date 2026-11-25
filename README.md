# Veristack (`vstack`)

**Replace test theater and silent regressions with deterministic verification gates.**
Warning, veristack is "slop" :)

Veristack is a deterministic **9-rung verification ladder (`R0 → R8`)**, cross-language static and invariant analyzer (`vstack`), native linter/analyzer kit, runnable formal proof suite (including **Bend 2**), and portable agent skill for **TypeScript/JS, C#/.NET, Rust, Python, Go, SQL, and Shell**.

> **Core rule:** Push every check as far down the ladder toward `R0` as possible while keeping the real failure mechanism intact. Checks run faster, flake masking disappears, and coding agents spend fewer tokens repairing broken code.

---

## The Problem It Solves

AI-assisted repositories fail in three recurring ways:

1. **Test theater:** heavily mocked unit tests and slow E2E suites that mirror buggy implementations, pass when behavior breaks, and hide failures behind `retries: 3`, `|| true`, or `continue-on-error: true`.
2. **Defects by omission:** boolean flag soup admitting impossible states, wall-clock duration math, release-stripped production assertions, unchecked slices, and swallowed errors.
3. **Silent invariant loss:** an agent fixes one issue while quietly deleting an earlier null guard, bounds check, `try/finally` cleanup, or comparison clause.

Veristack converts practices from software engineering, Lean/Toyota production systems, silicon verification, and safety-critical software into fast, repeatable CLI and CI gates.

---

## The 9-Rung Verification Ladder

Every check belongs on the lowest rung that still catches the defect:

```text
R0  Static Locks, Anti-Slop & Anti-Cheat          (< 2 s   | 100% files)
R1  Types, Explicit State Machines & Structure    (1–10 s  | 100% files)
R2  Pure Logic, Data Tables, MC/DC & PBT          (10ms–2s | 15–40 specs)
R3  Stateful MBT, Cross-Coverage, Host & Twins    (0.2–5 s | 5–15 suites)
R4  Real Engines, Migrations, 1..N Faults & DST   (2–30 s  | 3–8 slices)
R5  Formal Proofs (Bend 2 / Quint / Stateright)   (30s–15m | diff/nightly)
R6  Empirical Big-O, SPC Drift, RTY & Load        (2–30 m  | 1–2 / svc)
R7  Thin Golden-Path E2E & Hardware Proof         (2–15 m  | 5–15 MAX)
R8  Live Production Verification & Boot BIST      (Always  | 3–10 probes)
```

---

## Quick Start

Runs on **Node.js `>= 18`** or **[Bun](https://bun.sh) `>= 1.2.0`** via npm, pnpm, or Bun. Optional native toolchains (`dotnet`, `cargo`, `uv`, `go`, `bend`) verify their matching reference suites.

```bash
# Run immediately with npx or bunx
npx veristack scan .
bunx veristack scan .

# Or install as a dev dependency in your repo
npm install -D veristack        # or: pnpm add -D veristack / bun add -d veristack
npx vstack scan . --json        # Machine-readable report for coding agents
npx vstack diff-cheats . --base origin/main --fail
```

Run `npx veristack --help` (or `vstack --help`) for the complete command and flag list. From a local clone, run `bun run check` to self-verify Veristack.

---

## Per-Repo Configuration (`.vstack.json`)

Teams can turn off style rules that conflict with an existing ADR, adjust severities, or ignore directories by adding `.vstack.json` (or `.verification/vstack.json`) at the repo root:

```json
{
  "rules": {
    "no-comments": "off",
    "max-file-lines": "off",
    "long-file": "off",
    "rust-prod-unwrap-or-expect": "warn"
  },
  "ignore": ["spikes/**"]
}
```

Once committed, `vstack diff-cheats` watches `.vstack.json` (and `.verification/invariants.json` / `.vstackignore`) so future PRs cannot quietly disable rules without human review. You can also pass `--config <file>` or `--disable rule1,rule2` for ad-hoc scans.

---

## Multi-Language Coverage (7 Benchmarked Languages)

Every language below is covered by a living `caught/` vs `clean/` precision benchmark under [examples/](examples/README.md) (`vstack bench . --fail`: **196/196 recall, 0 clean FPs, 0 adversarial comment/string-wrapped FPs**):

| Language | Static & Native Enforcement (`R0`–`R1`) | Runnable Reference & Formal Proof (`R2`–`R5`) | Guide |
| :--- | :--- | :--- | :--- |
| **TypeScript / JS** | `oxc-parser` AST, cross-file import graph, [oxlint-no-comments.mjs](lint/oxlint-no-comments.mjs), [oxlint-explicit-state-machine.mjs](lint/oxlint-explicit-state-machine.mjs) | `src/` + `tests/` ([formal-verification.test.ts](tests/formal-verification.test.ts)) | [typescript.md](skill/references/languages/typescript.md) |
| **C# / .NET 10** | Roslyn [VStack.Analyzers](lint/csharp/VStack.Analyzers/) (`VSTACK001`–`VSTACK004`), `TreatWarningsAsErrors` | [templates/csharp-reference/](templates/csharp-reference/) (BFS formal proof, Dafny, `FsCheck`, `Stryker.NET`) | [csharp.md](skill/references/languages/csharp.md) |
| **Rust (2024)** | `unsafe_code = "forbid"`, Clippy `unwrap_used`/`expect_used`/`wildcard_enum_match_arm = "deny"`, `rust-prod-unwrap-or-expect` | [templates/rust-reference/](templates/rust-reference/) (`stateright` BFS, Kani, `proptest`, `cargo-mutants`) | [rust.md](skill/references/languages/rust.md) |
| **Python (3.12+)** | `ruff` strict + `S101` prod assert ban, `mypy --strict`, `assert_never` | [templates/python-reference/](templates/python-reference/) (`hypothesis` PBT/MBT, BFS formal check, `mutmut`) | [python.md](skill/references/languages/python.md) |
| **Go (1.23+)** | Concurrency/channel/UTF-8/path guards + [.golangci.yml](templates/go-reference/.golangci.yml) (`errcheck`, `bodyclose`, `gosec`, `exhaustive`, `bidichk`) | [templates/go-reference/](templates/go-reference/) (JSON transition table, `testing/quick` PBT + stateful MBT, `go test -race`) | [templates/go-reference/](templates/go-reference/order.go) |
| **SQL & Shell** | Postgres lock-timeout, RLS fail-open, `LIMIT` without `ORDER BY`, `= NULL`, `pkill -f`, argv secret & `PATH` guards | [examples/sql/](examples/sql/manifest.json), [examples/shell/](examples/shell/manifest.json) | [examples/README.md](examples/README.md) |

---

## Invariant Detection & Mechanical Proofs

Static pattern rules alone catch known footguns, not broken domain invariants. Veristack combines four complementary invariant layers:

1. **Diff Invariant-Loss & AST Predicate Weakening (`vstack diff-cheats`):** Detects dropped null/bounds/error/cleanup/lock/timeout/auth guards (`diff-invariant-guard-dropped`) and stripped `if` branches, `&&`/`||` clauses, or `<=`/`>=`/`===` bounds (`diff-predicate-weakened`) when a PR removes protection without adding matching test assertions. On a 320-pair historical OSS bug-fix replay corpus (`vstack bench --replay`), this catches **58.1% (`186/320`)** combined (**56.3%** regression immunity, **312/320** regression-free).
2. **Repo-Wide Statistical Belief Mining (`vstack scan`):** Infers the codebase's own invariants across call sites (`>= 75%` adherence, `N >= 4`) to flag outlier omitted null checks (`invariant-deviant-null-check`), missing `finally`/`defer`/`with` cleanups (`invariant-deviant-paired-cleanup`), and unprotected sibling route handlers (`invariant-deviant-route-auth`).
3. **Bend 2 Universal Laws (`vstack laws --verify`):** Pairs a CODEOWNERS-locked [LAWS.bend](templates/bend2-reference/LAWS.bend) spec with [PROOF.bend](templates/bend2-reference/PROOF.bend) over [Model.bend](templates/bend2-reference/Model.bend) (idempotency, monotonic terminal states, total saturating math, zero-cap bounds, codec round-trip, and stack unwind), verified directly by `bend --check-only` (and `--verdict` with the Lean BendTT kernel when `$BENDTT` is set) alongside [.verification/laws/universal-laws.laws.json](.verification/laws/universal-laws.laws.json) across all 6 toolchains.
4. **Daikon-Style Dynamic Invariants (`vstack invariants`):** Infers runtime bounds, non-null, enum-domain, sorted-array, and relational (`result <= args.amount`) invariants from JSON execution traces, diffs them against a locked `.verification/invariants.json` baseline, and fails CI when a behavioral invariant breaks.

---

## Key Capabilities & Gates

- **Anti-cheat & supply-chain locks:** catches `continue-on-error: true`, `|| true`, `--no-verify`, test skips/retries, unpinned third-party GitHub Actions, missing `permissions:`/`timeout-minutes`/`concurrency`, blanket suppressions, and stealth edits to `.vstack.json` / `.verification/invariants.json`.
- **Brownfield ratchets & choke points:** auto-shrinking `--ratchet` baselines for legacy adoption, `.verification/chokepoints.json` for project-specific banned primitives, and `vstack formal-sync` commit-drift checks.
- **Zero-defect engineering utilities:** `red-before-fix`, `mcdc` independence vectors, `spc` drift control charts, empirical `big-o` scaling fits, and 4 deterministic-first 90/10 BYO System 1 circuits (`vstack circuit list`).

---

## Portable Agent Skill

Install [skill/](skill/) into `~/.agents/skills/veristack` or `~/.claude/skills/veristack` so coding agents run `vstack scan . --json` before designing or refactoring verification suites:

- [skill/SKILL.md](skill/SKILL.md) — 9-rung ladder, shared vocabulary, and 4-phase workflow
- [skill/references/01-test-and-verification-index.md](skill/references/01-test-and-verification-index.md) — All 42 mechanisms (`V01`–`V42`)
- [skill/references/02-linter-and-antislop-stack.md](skill/references/02-linter-and-antislop-stack.md) — `R0`–`R1` linter architecture & ratchets
- [skill/references/03-pushdown-protocol-and-budgets.md](skill/references/03-pushdown-protocol-and-budgets.md) — Routing matrix, budgets & CI speed
- [skill/references/05-formal-verification.md](skill/references/05-formal-verification.md) — Formal verification playbook (`R5 / V25`)
- [skill/references/06-system1-circuits.md](skill/references/06-system1-circuits.md) — 90/10 BYO System 1 circuit runtime
- [skill/references/07-zero-defect-cross-discipline.md](skill/references/07-zero-defect-cross-discipline.md) — Lean, Silicon & Safety-Critical verification

---

## Local Verification Across All Toolchains

```bash
bun run check        # TS/JS/Bun + self-scan + 110 tests
bun run test:laws    # Bend 2 proofs + Go + Rust + Python + C# + TS law witnesses
bun run test:go      # go vet + go test -race (table, PBT, stateful MBT)
bun run test:rust    # rustfmt + clippy -D warnings + proptest + stateright
bun run test:python  # ruff + mypy --strict + pytest + hypothesis
bun run test:csharp  # Roslyn VStack.Analyzers + .NET 10 reference solution
```

---

## Attribution & Clean-Room Notice

Veristack is an original, from-scratch MIT implementation synthesizing ideas from open-source tooling and reliability literature:

- **Open-source inspiration:** [`deterministic-machines/deslop-please`](https://github.com/deterministic-machines/deslop-please), [`dmmulroy/anti-slop`](https://github.com/dmmulroy/anti-slop), [`@interfere/landmines`](https://github.com/interfere-inc/landmines), [`mattpocock/skills`](https://github.com/mattpocock/skills), [`cursor/plugins` (`pstack`)](https://github.com/cursor/plugins/tree/main/pstack), [`bendlang/bend`](https://github.com/bendlang/bend), [`antithesishq/bombadil`](https://github.com/antithesishq/bombadil), and [`tigerbeetle/tigerbeetle`](https://github.com/tigerbeetle/tigerbeetle) (`TIGER_STYLE.md`).
- **Research & literature:** Dawson Engler et al. (*Bugs as Deviant Behavior*, SOSP 2001), Michael Ernst et al. (*Daikon Dynamic Invariant Detection*), Matteo Vaccari (*Tests as Data*), John Ousterhout (*A Philosophy of Software Design*), Meta Engineering (*Just-in-Time Catching Test Generation*, `arXiv:2601.22832`), TypeSafe AI (JEV), Shopify Packwerk, Shigeo Shingo (*Poka-Yoke*), Toyota (*Jidoka* / *A3*), Shewhart (*SPC*), NASA JPL (*Power of 10*), DO-178C (*MC/DC*), SQLite (*TH3*), and seL4.

See [skill/references/04-source-patterns-digest.md](skill/references/04-source-patterns-digest.md) for the full traceability map.

## License

[MIT](LICENSE) © 2026 [a1ter-nate](https://github.com/a1ter-nate)
