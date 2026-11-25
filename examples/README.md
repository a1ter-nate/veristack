# Living Examples & Per-Language Accuracy Suite

Every file under `examples/<language>/` serves **two jobs simultaneously**:

1. **Clear side-by-side reference for humans:** browse `caught/` to see the exact bugs, anti-patterns, and test-theater smells Veristack flags — and `clean/` to see the idiomatic, zero-finding equivalents (including tricky edge cases Veristack intentionally does *not* false-positive on).
2. **Executable accuracy test suite (`tests/examples-accuracy.test.ts`):** `bun test` runs the real `vstack` scanner against every `caught/` and `clean/` file and asserts **exact rule-ID matches** against each language's `manifest.json` (true positives *and* zero false positives).

## Languages Covered

| Language | Caught Examples (True Positives) | Clean Examples (True Negatives / Edge Cases) | Accuracy Manifest |
| :--- | :--- | :--- | :--- |
| **TypeScript** | [caught/](typescript/caught/) — boolean soup, optional bag, non-exhaustive switch, `O(N^2)` loop scan, `new RegExp()` in loop, `Date.now() -` CDC, unbounded loop, `as any`, prose comments, mocked/skipped/tautological/non-hermetic tests | [clean/](typescript/clean/) — discriminated union + `assertNever`, `Map`-indexed loop + `performance.now()`, `WARNING:`/`SAFETY:`/JSDoc allowed comments, coverage-policy tooling test, comment containing `"for"` | [manifest.json](typescript/manifest.json) |
| **C# / .NET** | [caught/](csharp/caught/) — bool flag soup, nullable state bag, scattered mutation, `Debug.Assert` (release-stripped), `DateTime.UtcNow -` CDC, `FirstOrDefault` in loop, `Thread.Sleep` & `Assert.True(true)` | [clean/](csharp/clean/) — closed `abstract record` + exhaustive `switch`, `Dictionary` lookup + `TimeProvider`/release-active guard, clean behavioral xUnit `[Theory]` | [manifest.json](csharp/manifest.json) |
| **Rust** | [caught/](rust/caught/) — bool flag soup, `Option<T>` state bag, wildcard enum `match`, `debug_assert!`, `SystemTime::now().duration_since`, `sqlx::query` in `for` loop, `env::set_var` & `thread::sleep` in test | [clean/](rust/clean/) — closed `enum` + exhaustive `match`, `impl Trait for Struct` with `sqlx::query` (not a loop!), `&str` literal `match` with `_ =>`, `HashMap` + `Instant::now()` + `#[cfg(test)]` | [manifest.json](rust/manifest.json) |
| **Python** | [caught/](python/caught/) — bool flag soup, `Optional` state bag, silent `case _:` wildcard, bare prod `assert`, `time.time() -` CDC, `list.pop(0)` & `re.compile` in loop, `time.sleep` / `@pytest.mark.skip` / `assert True` | [clean/](python/clean/) — frozen `@dataclass` union + `assert_never`, `collections.deque` + `time.monotonic()` + `deadline`-bounded loop + `InvariantViolationError`, clean parametrized pytest | [manifest.json](python/manifest.json) |

## Growing the Accuracy Suite Over Time

To lock down a new rule or a real-world calibration edge case:
1. Add a minimal file under `examples/<language>/caught/` (should trigger) or `examples/<language>/clean/` (must stay 0 findings).
2. Add its expected rule IDs to `examples/<language>/manifest.json`.
3. Run `bun test tests/examples-accuracy.test.ts` (or `bun run check`).
