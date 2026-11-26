# Go Verification Guide (`R0` → `R8`)

## Recommended Packages per Rung (R0–R8)

| Rung | Recommended Packages / Tools |
| :---: | :--- |
| **R0** | `gofmt`, `golangci-lint`, `lefthook` |
| **R1** | `go vet`, `deadcode`, `internal/` package boundary enforcement |
| **R2** | `testing` (table-driven subtests), `pgregory.net/rapid` or `testing/quick` (PBT) |
| **R3** | `pgregory.net/rapid` (`StateMachine` MBT), `net/http/httptest`, `pact-go` |
| **R4** | `testcontainers-go`, `golang-migrate` / `goose` migration verification |
| **R5** | `go-mutesting` / `gremlins`, `Bend 2` / `Quint` / `TLA+` |
| **R6** | `testing.B` + `benchstat`, `k6` |
| **R7** | Thin cross-service black-box E2E (`go test -race`, `1–3` tasks) |
| **R8** | `go.opentelemetry.io/otel`, synthetic probes & canary workflows |

## Reference Implementation

See `templates/go-reference/` for runnable table-driven tests, PBT/MBT state machine checks, and `.golangci.yml`.
