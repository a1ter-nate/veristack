# AGENTS.md

1. Run `bun run check` before pushing (enforces `no-comments`, `no-implicit-state-machine`, all Bun tests, zero cheats, zero warnings, and zero rung holes). Run `bun run test:csharp`, `bun run test:rust`, and `bun run test:python` when touching C#, Rust, or Python adapters/templates.
2. `skill/` and `tests/fixtures/` are locked oracles — do not weaken or delete cases to pass CI.
3. Zero prose comments in `src/`, `tests/`, `lint/`, and `templates/` (only tool directives, `WARNING:`, `SAFETY:`, and public API docs).
4. Zero `as any` or `as unknown as` casts in TS, zero `dynamic` or `<NoWarn>` in C#, zero prod `.unwrap()` or unjustified `unsafe` in Rust, and zero prod bare `assert` or `Any` in Python.
5. Never pipe tests into `tail` or `head`, never use `--no-verify`, never add `continue-on-error: true` or `|| true` after checks.
6. Keep modules deep and interfaces narrow (<= 6 runtime exports per module, <= 500 lines per file).
