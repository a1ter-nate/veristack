# Python — Verification Stack Implementation (R0 → R8)

Concrete `pyproject.toml` strict tooling, idiomatic algebraic `@dataclass(frozen=True)` state machines, and runnable Python 3.12+ (`uv`) reference project implementing the universal principles from [../../SKILL.md](../../SKILL.md) in Python.

- **Runnable R0–R5 Reference Project:** `templates/python-reference/` (`order-lifecycle-ref`: closed frozen-dataclass union + `assert_never`, JSON Tests-as-Data `@pytest.mark.parametrize`, `hypothesis` PBT + `RuleBasedStateMachine` Stateful MBT, exhaustive BFS formal model check + functional cross-coverage closure, `mutmut` config).
- **Cross-Language `vstack` CLI Support:** `vstack scan`, `vstack state-machines`, `vstack no-comments`, `vstack diff-cheats`, `vstack classify`, and `vstack circuit` natively analyze `.py` and `pyproject.toml`.

---

## 1. Universal Rule → Python Implementation Matrix

| Universal Rule | Rung | Native Python Enforcement (`ruff` / `mypy` / `pytest`) | `vstack` Scanner Coverage |
| :--- | :---: | :--- | :--- |
| **`no-comments`** | R0 | `vstack no-comments . --fail` (allows `#!/`, `SPDX`, `WARNING:`, `SAFETY:`, `type: ignore[code]`, `noqa: CODE`, public docstrings; bans prose `#` comments) | `src/no-comments.ts` |
| **`no-implicit-state-machine`** | R0/R1 | `mypy --strict` + `typing.assert_never` in `match` | `vstack state-machines . --fail` (`src/state-machines/python.ts`: boolean soup, `Optional`/`\| None` state-bag, scattered `self.status` mutations, missing `assert_never` / silent `case _:`) |
| **`no-unsafe-escape-hatch`** | R0/R1 | `mypy --strict` (`disallow_any_explicit = true`) | `no-chained-or-any-cast` (`: Any`, `-> Any`, `cast(Any, ...)`) |
| **`no-swallowing-catch` & `suppression-audit`** | R0 | `ruff` (`E`/`F`/`B`/`S`), `mypy --strict` | `no-swallowing-catch` (`except: pass`), `suppression-audit` (bare `# type: ignore` / `# noqa`), `diff-python-bare-suppression` |
| **`no-release-stripped-assert` (`V36`)** | R1 | `ruff` `S101` enabled on `src/` (ignored only in `tests/`) | `no-release-stripped-assert` (bans bare `assert` in prod `.py` because `python -O` strips it; require explicit `InvariantViolationError`) |
| **`cdc-wall-clock-duration` (`V30`)** | R1 | `time.monotonic()` / `time.perf_counter()` | `cdc-wall-clock-duration` (flags `datetime.now() - ...` and `time.time() - ...` in prod) |
| **`no-test-only-production-seam`** | R0/R1 | Private `_` internals + scanner | `no-test-only-production-seam` (`_for_testing`, `_test_only`) |
| **`test-integrity` (Landmines)** | R0 | `pytest --strict-markers` + `vstack scan` | `no-fixed-sleep` (`time.sleep`/`asyncio.sleep`), `test-discipline` (`@pytest.mark.skip`/`xfail`/`@unittest.skip`), `no-flake-masking` (`@pytest.mark.flaky`/`--reruns`), `weak-asserts-tautology` (`assert True`/`assert 1 == 1`), `self-derived-expectation` (`assert f(x) == f(x)`), `no-elapsed-time-bound`, `no-imported-mutation` (`os.environ[...]=`/`os.putenv`), `no-test-nondeterminism` (`datetime.now`/`random.*`/`time.time`), `no-multi-status-assertion` (`status_code in (200, 404)`), `no-unexercised-test` |

---

## 2. Drop-In `pyproject.toml` Static Guardrails

```toml
[tool.ruff.lint]
select = ["E", "F", "B", "I", "UP", "S", "SIM", "RET", "ANN"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101"]

[tool.mypy]
strict = true
warn_unreachable = true
disallow_any_explicit = true
```

### Explicit State Machine Idiom (Python 3.12+)

```python
@dataclass(frozen=True, slots=True)
class Pending:
    amount_cents: int

@dataclass(frozen=True, slots=True)
class Authorized:
    amount_cents: int
    auth_code: str

OrderState = Pending | Authorized | Shipped | Cancelled

def state_name(state: OrderState) -> str:
    match state:
        case Pending(): return "pending"
        case Authorized(): return "authorized"
        case Shipped(): return "shipped"
        case Cancelled(): return "cancelled"
        case _: assert_never(state)
```

---

## 3. R0–R8 Tooling & Reference Proof (`templates/python-reference/`)

| Rung | Mechanism | Proof / Recommended Python Tools | Command |
| :---: | :--- | :--- | :--- |
| **R0** | Strict `ruff` (including prod `S101`), `ruff format`, `no-comments`, anti-cheat | `pyproject.toml` | `uv run ruff check && uv run ruff format --check` |
| **R1** | `mypy --strict` (`disallow_any_explicit`) + closed dataclass union + `assert_never` | `src/order_lifecycle/machine.py` | `uv run mypy src tests && vstack state-machines . --fail` |
| **R2** | Tests-as-Data JSON table + PBT | `tests/fixtures/transitions.json`, `pytest.mark.parametrize`, `hypothesis` `@given` | `uv run pytest` |
| **R3** | Stateful MBT + Functional Cross-Coverage + In-Process Host + Twins | `hypothesis.stateful.RuleBasedStateMachine`, FastAPI `TestClient`, `respx` | `uv run pytest` |
| **R4** | Real DB, Migrations, Bus DLQ & Fault Sweeps | `testcontainers-python`, `alembic` upgrade/downgrade replay, `FaultingStorage` 1..N sweeps | `uv run pytest -m integration` |
| **R5** | Formal Model Check, SMT, Mutation, Fuzzing & System 1 Circuits | `tests/test_formal_model_check.py`, `z3-solver` / `CrossHair`, `mutmut`, `Atheris`, `vstack circuit` | `uv run pytest && uv run mutmut run` |
| **R6** | Benchmarks, SPC & Load | `pytest-benchmark`, `locust`/`k6`, `vstack spc` | `uv run pytest --benchmark-only` |
| **R7** | Thin Golden-Path E2E (5–15 journeys max) | `playwright-python` | `uv run pytest -m e2e` |
| **R8** | Production Verification & Boot BIST | OpenTelemetry, fail-closed `run_boot_bist()` / `/readyz` | Continuous |
