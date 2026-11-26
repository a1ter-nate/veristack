# Veristack (`vstack`)

**Replace test theater, slop asymmetry, and silent regressions with deterministic verification gates.**
Warning, veristack is "slop" :)

Veristack is a deterministic **9-rung verification ladder (`R0 → R8`)**, cross-language static and invariant analyzer (`vstack`), native linter/analyzer kit, runnable formal proof suite (**Bend 2**), anti-slop PR review briefer, and portable agent skill for **TypeScript/JS, C#/.NET, Rust, Python, Go, SQL, and Shell**.

> **Core rule:** Push every check as far down the ladder toward `R0` as possible while preserving the real failure mechanism, prefer subtraction over additive workarounds, and reserve human review for the highest-stakes decisions.

---

## Why Veristack Exists

Inspired in part by [The No AI Slop Manifesto](https://gist.github.com/dexhorthy/4cc96f01be5b1208519e75dad250a948) (*AIE Code Summit 2026* — Dex Horthy, Lauren Tan / `@poteto`, et al.), Veristack targets four compounding failure modes in AI-assisted engineering:

1. **Test theater:** heavily mocked unit tests and slow E2E suites that mirror buggy code and mask failures behind `retries: 3`, `|| true`, or `continue-on-error: true`.
2. **Defects by omission:** boolean flag soup admitting impossible states, wall-clock duration math, release-stripped production assertions, unchecked slices, and swallowed catches.
3. **Silent invariant loss:** an agent fixes one issue while quietly deleting an earlier null guard, bounds check, `try/finally` cleanup, or comparison clause.
4. **Slop asymmetry & compounding context rot:** thousand-line additive PRs, ten-page doc dumps, layered workarounds, and stale `AGENTS.md` pointers that shift review burden onto humans and teach the next agent bad habits.

---

## Quick Start

Runs on **Node.js `>= 18`** or **[Bun](https://bun.sh) `>= 1.2.0`** via npm, pnpm, or Bun. Optional native toolchains (`dotnet`, `cargo`, `uv`, `go`, `bend`) verify their matching reference suites.

```bash
# Run immediately with npx or bunx
npx veristack scan .
bunx veristack scan .

# Or install as a dev dependency
npm install -D veristack        # or: pnpm add -D veristack / bun add -d veristack
npx vstack scan . --strict      # Zero-ratchet, zero-finding strict gate
npx vstack hooks on             # Install two-tier agent hooks (Claude Code, Codex, Cursor)
npx vstack diff-cheats . --base origin/main --fail
npx vstack review-brief . --base origin/main --md
```

Run `npx vstack --help` for the complete command and flag reference. From a local clone, run `bun run check` to self-verify Veristack.

---

## The 9-Rung Verification Ladder

Every check belongs on the lowest rung that still catches the defect:

```text
R0  Static Locks, Anti-Slop & Agent-Doc Hygiene   (< 2 s   | 100% files)
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

## Core Capabilities

### 1. Invariant Detection & Mechanical Proofs
- **Diff Invariant-Loss & AST Predicate Weakening (`vstack diff-cheats`):** catches dropped null/bounds/error/cleanup/lock/timeout/auth guards (`diff-invariant-guard-dropped`) and weakened `if`/`&&`/`||`/bound predicates (`diff-predicate-weakened`) when a diff drops protection without matching test assertions. On a 320-pair historical OSS bug-fix replay corpus (`vstack bench --replay`), this catches **58.1% (`186/320`)** combined (**312/320** regression-free).
- **Repo-Wide Statistical Belief Mining (`vstack scan`):** infers the codebase's own invariants (`>= 75%` adherence, `N >= 4`) to flag outlier omitted null checks, missing `finally`/`defer`/`with` cleanups, and unprotected sibling routes.
- **Bend 2 Universal Laws (`vstack laws --verify` + `vstack scan`):** pairs CODEOWNERS-locked [LAWS.bend](templates/bend2-reference/LAWS.bend) with [PROOF.bend](templates/bend2-reference/PROOF.bend) over [Model.bend](templates/bend2-reference/Model.bend), verified by `bend --check-only` alongside [.verification/laws/universal-laws.laws.json](.verification/laws/universal-laws.laws.json) **and** statically projected across TS/JS, C#, Rust, Python, and Go (`law-monotonic-terminal-state`, `law-saturating-underflow`, `law-zero-cap-clamp`, `law-codec-roundtrip-asymmetry`, `law-unwind-unpaired`).
- **Daikon-Style Dynamic Invariants (`vstack invariants`):** infers runtime bounds, non-null, enum-domain, sorted-array, and relational invariants from JSON traces and fails CI when a locked `.verification/invariants.json` invariant breaks.

### 2. Anti-Slop Review & Knowledge-Base Hygiene
- **Stakes-Ranked Human Review Brief (`vstack review-brief`):** measures PR slop-asymmetry (non-lockfile lines added, shotgun-surgery directory spread, doc-dump volume, additive-only deletion ratio, newly added `HACK`/`WORKAROUND` or fallback-swallow catches, and `diff-cheats` hits), sorts changed files into a **Must Review First** queue, explicitly lists where automated checks are blind, and outputs a paste-ready `--md` ownership & AI-disclosure checklist.
- **Agent Instruction Hygiene (`vstack scan`):** audits `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `REVIEW.md`, `.cursorrules`, and `copilot-instructions.md` for context bloat (`agent-doc-bloat`), dead repo file references (`agent-doc-stale-path`), and mechanical rules stuck in prose (`agent-doc-unpromoted-rules`).
- **Real-Time Agent Harness Hooks (`vstack hooks on` + `vstack check-file` + `vstack doctor`):** installs millisecond two-tier hooks (immediate per-edit single-file scan + deduplicated `Stop` deep/diff pass, plus Cursor `preToolUse` write blocking) for Claude Code, Codex, Cursor, GitHub Copilot, and Grok Build so any model auto-fixes slop on the next turn without waiting for CI.
- **Anti-Cheat, Supply-Chain & Brownfield Locks:** blocks `continue-on-error: true`, `|| true`, `--no-verify`, test skips/retries, unpinned third-party GitHub Actions, missing `persist-credentials: false` on OIDC workflows, stealth `.vstack.json`/`.verification/invariants.json` weakening, and supports auto-shrinking `--ratchet` baselines, `.verification/chokepoints.json`, `vstack formal-sync`, `red-before-fix`, `mcdc`, `spc`, `big-o`, and 90/10 BYO System 1 circuits (`vstack circuit list`).

---

## Per-Repo Configuration (`.vstack.json`)

Adjust rule severities or ignore directories via `.vstack.json` (or `.verification/vstack.json`) at the repo root:

```json
{
  "rules": {
    "no-comments": "off",
    "max-file-lines": "off",
    "rust-prod-unwrap-or-expect": "warn"
  },
  "ignore": ["spikes/**"]
}
```

Once committed, `vstack diff-cheats` watches `.vstack.json`, `.vstackignore`, and `.verification/invariants.json` so future PRs cannot quietly relax gates without human review.

---

## Multi-Language Coverage (7 Benchmarked Languages)

Every language is verified by a living `caught/` vs `clean/` precision benchmark under [examples/](examples/README.md) (`vstack bench . --fail`: **196/196 recall, 0 clean FPs, 0 adversarial comment/string-wrapped FPs**):

| Language | Static & Native Enforcement (`R0`–`R1`) | Runnable Reference & Formal Proof (`R2`–`R5`) | Guide |
| :--- | :--- | :--- | :--- |
| **TypeScript / JS** | `oxc-parser` AST (`anti-slop`, `landmines`, `internal/` boundaries, cross-file graph) + unified Oxlint plugin (`veristack/lint`) | `src/` + `tests/` ([formal-verification.test.ts](tests/formal-verification.test.ts)) | [typescript.md](skill/references/languages/typescript.md) |
| **C# / .NET 10** | Roslyn [VStack.Analyzers](lint/csharp/VStack.Analyzers/) (`VSTACK001`–`VSTACK004`), `TreatWarningsAsErrors` | [templates/csharp-reference/](templates/csharp-reference/) (BFS proof, Dafny, `FsCheck`, `Stryker.NET`) | [csharp.md](skill/references/languages/csharp.md) |
| **Rust (2024)** | `unsafe_code = "forbid"`, Clippy `unwrap_used`/`expect_used`/`wildcard_enum_match_arm = "deny"` | [templates/rust-reference/](templates/rust-reference/) (`stateright`, Kani, `proptest`, `cargo-mutants`) | [rust.md](skill/references/languages/rust.md) |
| **Python (3.12+)** | `ruff` strict + `S101` prod assert ban, `mypy --strict`, `assert_never` | [templates/python-reference/](templates/python-reference/) (`hypothesis` PBT/MBT, BFS proof, `mutmut`) | [python.md](skill/references/languages/python.md) |
| **Go (1.23+)** | Concurrency/channel/UTF-8/path guards + [.golangci.yml](templates/go-reference/.golangci.yml) | [templates/go-reference/](templates/go-reference/order.go) (table, `testing/quick` PBT + stateful MBT, `-race`) | [examples/go/](examples/go/manifest.json) |
| **SQL & Shell** | Lock-timeout, RLS fail-open, `LIMIT` without `ORDER BY`, `= NULL`, `pkill -f`, argv secret & `PATH` guards | [examples/sql/](examples/sql/manifest.json), [examples/shell/](examples/shell/manifest.json) | [examples/README.md](examples/README.md) |

---

## Portable Agent Skill

Install [skill/](skill/) into `~/.agents/skills/veristack` or `~/.claude/skills/veristack` so coding agents run `vstack scan . --json` before designing checks and `vstack review-brief` before opening PRs:

- [skill/SKILL.md](skill/SKILL.md) — 9-rung ladder, leading vocabulary, and 4-phase workflow
- [skill/references/](skill/references/) — progressively disclosed playbooks (`01`–`07`) and per-language guides

---

## Local Verification Across All Toolchains

```bash
bun run check        # TS/JS/Bun test suite, no-comments, state-machines & self-scan
bun run test:laws    # Bend 2 proofs + Go + Rust + Python + C# + TS law witnesses
bun run test:go      # go vet + go test -race
bun run test:rust    # rustfmt + clippy -D warnings + proptest + stateright
bun run test:python  # ruff + mypy --strict + pytest + hypothesis
bun run test:csharp  # Roslyn VStack.Analyzers + .NET 10 reference solution
```

---

## Inspiration & Clean-Room Attribution

Veristack is an original, from-scratch MIT implementation synthesizing ideas from anti-slop engineering, open-source tooling, and reliability literature:

- **Anti-slop & human-judgment inspiration:** [The No AI Slop Manifesto](https://gist.github.com/dexhorthy/4cc96f01be5b1208519e75dad250a948) (*AIE Code Summit 2026* — Dex Horthy, Lauren Tan / `@poteto`, et al.) and [*Why Software Factories Fail*](https://github.com/humanlayer/advanced-context-engineering-for-coding-agents/blob/main/wsff.md).
- **Open-source tooling inspiration:** [`pbakaus/impeccable`](https://github.com/pbakaus/impeccable) (two-tier per-edit + `Stop` agent hooks & `doctor`), [`deterministic-machines/deslop-please`](https://github.com/deterministic-machines/deslop-please), [`dmmulroy/anti-slop`](https://github.com/dmmulroy/anti-slop), [`@interfere/landmines`](https://github.com/interfere-inc/landmines), [`mattpocock/skills`](https://github.com/mattpocock/skills) (including `writing-for-agents`), [`cursor/plugins` (`pstack`)](https://github.com/cursor/plugins/tree/main/pstack), [`bendlang/bend`](https://github.com/bendlang/bend), [`antithesishq/bombadil`](https://github.com/antithesishq/bombadil), and [`tigerbeetle/tigerbeetle`](https://github.com/tigerbeetle/tigerbeetle) (`TIGER_STYLE.md`).
- **Research & literature:** Dawson Engler et al. (*Bugs as Deviant Behavior*, SOSP 2001), Michael Ernst et al. (*Daikon Dynamic Invariant Detection*), Matteo Vaccari (*Tests as Data*), John Ousterhout (*A Philosophy of Software Design*), Meta Engineering (*Just-in-Time Catching Test Generation*, `arXiv:2601.22832`), TypeSafe AI (JEV), Shopify Packwerk, Shigeo Shingo (*Poka-Yoke*), Toyota (*Jidoka* / *A3*), Shewhart (*SPC*), NASA JPL (*Power of 10*), DO-178C (*MC/DC*), SQLite (*TH3*), and seL4.

See [skill/references/04-source-patterns-digest.md](skill/references/04-source-patterns-digest.md) for the full traceability map.

## License

[MIT](LICENSE) © 2026 [a1ter-nate](https://github.com/a1ter-nate)
