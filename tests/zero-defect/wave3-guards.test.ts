import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../../src/ladder.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave3-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("Wave 3 catches Python OSS bugs (eager asyncio, missing encoding, dynamic ORM kwargs, unscoped mkstemp, except Exception cleanup, test global state pollution)", () => {
  withTempRepo(
    {
      "app/worker.py": [
        "import asyncio",
        "import tempfile",
        "",
        "LOCK = asyncio.Lock()",
        "",
        "def load_text(path: str, qs: object, params: dict[str, object], header: str) -> str:",
        '    handle = open(path, "r")',
        "    fd, name = tempfile.mkstemp()",
        "    qs.annotate(**params)",
        '    if "no-store" in header:',
        '        return ""',
        "    try:",
        "        return handle.read()",
        "    except Exception:",
        "        handle.close()",
        "        raise",
      ].join("\n"),
      "tests/test_worker.py": [
        "import sys",
        "from app.worker import load_text",
        "",
        "def test_mutates_globals() -> None:",
        '    sys.modules["fake_mod"] = object()',
        '    assert callable(load_text)',
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "py-no-eager-asyncio-primitive-init",
        "py-open-missing-encoding",
        "py-unscoped-fd-or-connection-lifecycle",
        "py-orm-dynamic-kwarg-alias-injection",
        "http-case-sensitive-header-directive",
        "py-cleanup-require-finally-or-baseexception",
        "py-test-global-state-pollution",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Wave 3 catches C# EF unordered Skip, undisposed IDisposable, Math floor/ceiling inversion, Go unclosed HTTP body, test hook/timer/port hazards, and CI supply-chain checks", () => {
  withTempRepo(
    {
      "src/Repo.cs": [
        "using System;",
        "using System.IO;",
        "using System.Linq;",
        "public class Repo {",
        "  public int Clamp(int v, int minFloor) => Math.Min(v, minFloor);",
        "  public object Page(IQueryable<int> q) => q.Skip(10).Take(5).ToList();",
        "  public void Read(string p) {",
        "    var reader = new StreamReader(p);",
        "    Console.WriteLine(reader.ReadToEnd());",
        "  }",
        "}",
      ].join("\n"),
      "src/client.go": [
        "package client",
        'import "net/http"',
        "func Fetch(url string) error {",
        "  resp, err := http.Get(url)",
        "  if err != nil { return err }",
        "  _ = resp.StatusCode",
        "  return nil",
        "}",
      ].join("\n"),
      "tests/lifecycle.test.ts": [
        'import { afterEach, test, expect } from "vitest";',
        'import http from "node:http";',
        'import { runSafeWebOps } from "../../src/ops";',
        `afterEach(() => { test.${"skip"}('skip cleanup', () => {}); });`,
        'test("binds static port and stalls timer", () => {',
        "  const s = http.createServer();",
        "  s.listen(8080);",
        "  setTimeout(() => {}, 10000);",
        "  expect(typeof runSafeWebOps).toBe('function');",
        "});",
      ].join("\n"),
      ".github/workflows/ci.yml": [
        "name: ci",
        "on: pull_request",
        "concurrency:",
        "  group: ci-${{ github.ref }}",
        "  cancel-in-progress: true",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 10",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: third-party/tool@main",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "math-floor-ceiling-inversion",
        "efcore-unordered-skip-or-assert",
        "csharp-undisposed-local-idisp",
        "go-unclosed-http-body",
        "no-skip-in-after-hook",
        "no-unrefd-long-test-timer",
        "test-hardcoded-loopback-port",
        "ci-checkout-persist-credentials",
        "ci-unpinned-action-ref",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});
