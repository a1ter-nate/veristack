# 06 — Plug-and-Play JEV-Style System 1 Circuits (`90% Deterministic + 10% BYO System 1`)

> **Mental Model:** **Deterministic code executes (~90%). System 1 classifies the narrow fuzzy edge (~10%). LLMs generate only when prose/code is actually needed.**

Inspired by **probabilistic decision-layer circuits** (*classifiers as typed `if`-statements*) and **facts-corroborated System 1 classifiers**, `vstack` ships a plug-and-play **Circuit Runtime** (`src/circuits/`) and **4 ready-to-use verification & zero-defect circuits** that work with **any BYO System 1 model**.

---

## 1. The 5-Stage JEV Circuit Architecture

Every circuit in `src/circuits/` obeys the exact same formally verified 5-stage contract:

```text
Unstructured Input / Repo Event
   ↓ 1. Deterministic Fact Extraction (AST, git diff, static rules, telemetry)
   ↓ 2. Deterministic Short-Circuit (~80–95% of inputs resolved at $0 / 0ms)
   ↓ 3. Narrow BYO System 1 Call (typed choices + confidence + explicit abstain)
   ↓ 4. Deterministic 3-Band Policy + Static-Fact Corroboration
        • p >= highThreshold & corroborated  → Automated Action
        • p <= lowThreshold                  → Safe Default / Suppress
        • middle band / abstained / conflict → Escalate to Human (never guess)
   ↓ 5. Versioned SHA-256 Receipt & Short-Circuit Telemetry
```

### Formally Proven Safety Invariants (`tests/formal-verification.test.ts`)
Our exhaustive model check proves across all 160 combinations of `(abstained × contradictsStaticFacts × choice × confidence)`:
1. Hard-rule short-circuits **never** invoke the System 1 model.
2. Any `abstained`, `null`, or out-of-schema model output **always** resolves to `band: "abstained"` with `requiresHuman: true`.
3. Any model choice contradicting verified static facts **always** resolves to `band: "contradicted"` with `requiresHuman: true`.
4. Middle-band uncertainty (`low < p < high`) **always** resolves to `band: "uncertain"` with `requiresHuman: true`.

---

## 2. Four Default Verification & Zero-Defect Circuits

| Circuit ID | Deterministic ~90% Short-Circuit | Fuzzy ~10% System 1 Decision | Thresholds (`high` / `low`) |
| :--- | :--- | :--- | :---: |
| **`test-triage`** | Coverage-farm names, literal/self-derived tautologies, zero-SUT unit tests, clean table/PBT tests, over-window files | Classifies remaining ambiguous tests (`BEHAVIOR`, `CHANGE_DETECTOR`, `TAUTOLOGY`, `COVERAGE_FARM`) | `0.80 / 0.20` |
| **`pr-risk-router`** | `diff-cheats` (`block_merge`), protected paths (`CODEOWNERS`, workflows, `migrations/`, `auth`/`billing`/`security`) or churn `>= 400` (`two_review_or_canary`), small doc/test diffs `<= 60 L` (`auto_merge_candidate`) | Routes medium-ambiguity code diffs (`low_auto_merge`, `medium_single_review`, `high_two_review_or_canary`) | `0.85 / 0.20` |
| **`instruction-lint-promoter`** | Conflicting instructions (`resolve_conflict`), already-enforced rules (`prune_redundant_prose`), non-mechanical prose (`keep_as_guidance`) | Judges whether unmapped prohibition clauses in `AGENTS.md`/`SKILL.md` can become deterministic AST/compiler lints | `0.80 / 0.20` |
| **`perf-architecture-advisor`** | Static perf/complexity lint hits (`fix_static_perf_smell`), verified linear/n-log-n scaling (`timeExp <= 1.25` → `keep_verified`), over-window files | Classifies verified hotspots into optimization family (`algorithmic_complexity`, `data_layout_locality`, `batch_or_index_io`, `bounded_memory_streaming`, `no_change_needed`) with contradiction guard if `timeExp >= 1.75` | `0.80 / 0.20` |

---

## 3. Bring Your Own System 1 Model (BYO Adapters)

Every circuit accepts any `System1DecisionEngine` via CLI `--provider` or programmatically via `createSystem1Engine(...)` / custom `{ name, decide }`:

| Provider | How to Wire | Best For |
| :--- | :--- | :--- |
| **`jev`** | `--provider jev --endpoint "$JEV_API_URL"` (`JEV_API_KEY`) | TypeSafe JEV hosted/gateway decision model |
| **`laya`** | `--provider laya` (`--image laya-classifier:latest`) | Offline, network-isolated Docker classifier container |
| **`local`** | `--provider local --endpoint http://127.0.0.1:11434/v1/chat/completions --model qwen3.5:9b` | Local Ollama / vLLM / Gemma-4-Decision OpenAI-compatible servers |
| **`command`** | `--provider command --command "./my-classifier.py"` | Any custom executable reading `{ requests }` JSON on stdin and writing `{ results }` JSON on stdout |
| **`fixture`** | `--provider fixture` | Deterministic offline testing & CI verification (zero live inference) |
| **Custom JS** | Pass `{ name: "my-model", async decide(requests) { ... } }` to `runCircuit(...)` | Direct SDK embedding in any TypeScript/Bun service |

### CLI Examples

Run `vstack circuit list` or `vstack --help` for full flag syntax:

```bash
vstack circuit run test-triage . --provider fixture
vstack circuit run pr-risk-router . --base origin/main --provider local --model qwen3.5:9b
vstack circuit run perf-architecture-advisor . --provider jev --endpoint "$JEV_API_URL" --json
```
