# Go Verification Playbook

## 1. Universal Rule Matrix

| Rule / Invariant | Go Enforcement Mechanism | Failure Mode Caught |
|---|---|---|
| No swallowed errors | `errcheck`, `errorlint`, `vstack` `no-swallowing-catch` (`if err != nil {}`) | Silent error loss, ignored `Close()` / `Write()` errors |
| No unsafe pointers | `gosec`, `vstack` `no-unsafe-pointer` (`unsafe.Pointer`) | Memory corruption and type-system bypass |
| No bare linter suppressions | `nolintlint`, `vstack` `no-bare-suppression` (`//nolint`) | Unexplained rule disables hiding bugs |
| No skipped or sleeping tests | `vstack` `no-skipped-test` (`t.Skip`), `no-fixed-sleep` (`time.Sleep`) | Flaky timing hacks and silently disabled tests |
| No unexercised test files | `vstack` `no-unexercised-test` | Tests asserting constants without importing or calling prod code |
| Race & concurrency safety | `go test -race ./...` + `go vet ./...` | Data races, lock inversions, goroutine leaks |
| Module encapsulation | Go `internal/` packages + `depguard` | Cross-boundary coupling and leaky abstractions |
| Explicit state machines | Typed state enum + exhaustive `switch` (`exhaustive` linter) | Invalid transitions and boolean-flag soup |

## 2. Drop-In `.golangci.yml` Guardrails

```yaml
version: "2"
linters:
  enable:
    - errcheck
    - errorlint
    - exhaustive
    - govet
    - gosec
    - nilerr
    - nolintlint
    - revive
    - staticcheck
    - unused
  settings:
    nolintlint:
      require-explanation: true
      require-specific: true
    exhaustive:
      default-signifies-exhaustive: false
issues:
  max-issues-per-linter: 0
  max-same-issues: 0
```

## 3. Explicit State-Machine Idiom (Make Illegal States Unrepresentable)

```go
type OrderState string

const (
	StateDraft     OrderState = "draft"
	StateConfirmed OrderState = "confirmed"
	StateShipped   OrderState = "shipped"
	StateCancelled OrderState = "cancelled"
)

func Transition(cur OrderState, event string) (OrderState, error) {
	switch cur {
	case StateDraft:
		if event == "confirm" {
			return StateConfirmed, nil
		}
		if event == "cancel" {
			return StateCancelled, nil
		}
	case StateConfirmed:
		if event == "ship" {
			return StateShipped, nil
		}
		if event == "cancel" {
			return StateCancelled, nil
		}
	case StateShipped, StateCancelled:
		return cur, fmt.Errorf("terminal state %s rejects %s", cur, event)
	}
	return cur, fmt.Errorf("illegal transition %s -> %s", cur, event)
}
```

## 4. Recommended Packages by Verification Rung (R0–R8)

| Rung | Goal | Recommended Packages / Tools | Notes |
|---|---|---|---|
| **R0** | Instant static, formatting & anti-slop | `gofmt` / `goimports`, `golangci-lint`, `lefthook`, `veristack` (`vstack`) | Run `gofmt -l .` and `golangci-lint run` in pre-commit & CI. |
| **R1** | Types, vet, dead-code & boundaries | `go vet ./...`, `golang.org/x/tools/cmd/deadcode`, `staticcheck`, Go `internal/` | Enforce zero warnings and strict `internal/` encapsulation. |
| **R2** | Unit tables, PBT & planted-fault canary | `testing` (`[]struct` + `t.Run`), `pgregory.net/rapid` (`rapid.Check`), `testing/quick`, `vstack canary` | Pair data-driven table tests with `rapid` property tests and `vstack canary`. |
| **R3** | Stateful MBT, host boundary & contracts | `pgregory.net/rapid` (`rapid.StateMachine`), `net/http/httptest`, `pact-go`, `go test -race` | Drive handlers in-process via `httptest.NewServer`/`NewRecorder`. |
| **R4** | Real DB, migrations & containers | `testcontainers-go`, `golang-migrate`, `pressly/goose`, `go test -tags=integration` | Run real Postgres/Redis containers and apply migrations on seeded rows. |
| **R5** | Mutation, fuzzing & formal specs | `go test -fuzz=.`, `gremlins` / `go-mutesting`, `vstack canary`, Quint / TLA+ | Combine native Go fuzzing with mutation adequacy and formal specs. |
| **R6** | Benchmarks, load & scaling budgets | `go test -bench=. -benchmem`, `benchstat`, `k6`, `vstack big-o` | Compare allocations and p95 latency against explicit budgets in CI. |
| **R7** | Thin E2E golden paths | `playwright-go` or `@playwright/test` | Keep E2E thin; push logic down to R2/R3. |
| **R8** | Production telemetry & canaries | `go.opentelemetry.io/otel`, `prometheus/client_golang`, synthetic probes | Alert on SLO burn and automate rollback triggers. |
