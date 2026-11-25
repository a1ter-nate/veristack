# TypeScript / JavaScript — Verification Stack Implementation (R0 → R8)

Concrete toolchain, drop-in plugins, and test patterns implementing the universal principles from [../../SKILL.md](../../SKILL.md) in TypeScript / JavaScript (Bun / Node / Vitest).

---

## 1. Universal Rule → TypeScript Implementation Matrix

| Universal Rule | Rung | Native TS / JS Enforcement | `vstack` Scanner Coverage |
| :--- | :---: | :--- | :--- |
| **`no-comments`** | R0 | `lint/oxlint-no-comments.mjs` (`verification-stack/no-comments`) | `vstack no-comments . --fail` |
| **`no-implicit-state-machine`** | R0/R1 | `lint/oxlint-explicit-state-machine.mjs` (`verification-stack-state-machine/no-implicit-state-machine`) + `switch-exhaustiveness-check` | `vstack state-machines . --fail` |
| **`no-unsafe-escape-hatch`** | R0/R1 | `tsgo --noEmit` (`strict: true`, `noUncheckedIndexedAccess: true`), Oxlint `no-explicit-any`, `no-non-null-assertion`, `anti-slop` | `no-chained-or-any-cast` (`as any`, `as unknown as`) |
| **`no-swallowing-catch` & `suppression-audit`** | R0 | Oxlint `no-empty`, `ban-ts-comment` (`allow-with-description`) | `no-swallowing-catch`, `suppression-audit`, `diff-ts-ignore` |
| **`no-test-only-production-seam`** | R0/R1 | `go-internal` (`internal/` encapsulation) + custom lint | `no-test-only-production-seam` (`*ForTesting`, `__testing__`, `TestOnly`) |
| **`test-integrity` (Landmines)** | R0 | `@interfere/landmines` + Vitest `restoreMocks`/`unstubGlobals`/`unstubEnvs` + `TZ: "UTC"` | `no-fixed-sleep`, `no-flake-mask`, `test-discipline`, `weak-asserts-*`, `self-derived-expectation`, `no-multi-status-assertion`, `no-fetch-stub`, `no-test-nondeterminism`, `no-imported-mutation`, `no-unexercised-test`, `no-coverage-farm-file` |
| **Architecture & Dead Code** | R1 | `deslop-please` (`field-leak`/`shallow-module`/`tangle`/`cycle`), `knip`, `jscpd`, `dependency-cruiser` | `structure.ts` + `ci-auditor.ts` |

---

## 2. Drop-In Oxlint Configuration (`.oxlintrc.json`)

```json
{
  "jsPlugins": [
    "./node_modules/veristack/lint/oxlint-no-comments.mjs",
    "./node_modules/veristack/lint/oxlint-explicit-state-machine.mjs"
  ],
  "rules": {
    "verification-stack/no-comments": ["error", { "allow": ["WARNING", "SAFETY"] }],
    "verification-stack-state-machine/no-implicit-state-machine": "error"
  }
}
```

### Explicit State Machine Idiom (TypeScript)

Replace boolean flag soup or optional-field bags with a `readonly` discriminated union, a pure `transition()` function, and an `assertNever` exhaustiveness guard:

```ts
export type OrderState =
  | { readonly kind: "pending"; readonly amountCents: number }
  | { readonly kind: "authorized"; readonly amountCents: number; readonly authCode: string }
  | { readonly kind: "shipped"; readonly amountCents: number; readonly authCode: string; readonly trackingId: string }
  | { readonly kind: "cancelled"; readonly reason: string };

function assertNever(value: never): never {
  throw new Error(`Unhandled state: ${JSON.stringify(value)}`);
}
```

---

## 3. R2–R8 Tooling Map (TypeScript / JavaScript)

| Rung | Mechanism | Recommended TS / JS Tools |
| :---: | :--- | :--- |
| **R2** | Pure logic + Tests-as-Data tables + PBT | `bun test` / `vitest`, `test.each` backed by `fixtures/*.json` or `.csv`, `fast-check` (`fc.property`) |
| **R3** | Stateful MBT, Component UI, In-Process Host, Contracts & Twins | `fast-check` (`fc.commands` + `fc.modelRun`), `@testing-library/react` / Playwright CT, Hono `app.request()` / `supertest`, strict `MSW` (`onUnhandledRequest: "error"`), Pact / OpenAPI validator |
| **R4** | Real DB, Migrations, Bus DLQ & DST | `PGlite` / `Testcontainers` (Postgres/Redis/Kafka), real schema migration replay, Firebase/Firestore emulators, seeded virtual clock / DST harness |
| **R5** | Formal Verification, Mutation, Fuzzing & System 1 Circuits | Exhaustive TS state-space model check (`tests/formal-verification.test.ts`), `Quint` (`.qnt`) trace replay, `z3-solver` (WASM SMT), `StrykerJS`, `Jazzer.js`, `Bombadil`, `vstack circuit run test-triage . --provider jev\|laya\|local` |
| **R6** | Perf & Load | `tinybench` / `mitata`, `k6`, first-attempt reliability ledger (`retries: 0` in CI) |
| **R7** | Thin Golden-Path E2E (5–15 journeys max) | Playwright (`@playwright/test`) with web-first locators, real backend, zero `waitForTimeout` / `networkidle` |
| **R8** | Production Verification | Synthetics, canary rollouts, tail-sampled OpenTelemetry wide events |

---

## 4. Vitest Determinism Baseline (`vitest.config.ts`)

Every Vitest config should pin UTC and restore mocks automatically (verified by `vstack scan`):

```ts
export default defineConfig({
  test: {
    env: { TZ: "UTC" },
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
    retry: 0,
  },
});
```
