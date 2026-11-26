import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { discoverRepo } from "../../src/discover.ts";
import { scanRepo } from "../../src/ladder.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oss-cal-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

test("workflow audit allows benign GOFLAGS build tags, rejects dangerous GOFLAGS, and recognizes verification actions", () => {
  const safeGoWf = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 12,
    content: [
      "on: [pull_request]",
      "env:",
      "  GOFLAGS: '-tags=nobadger,nomysql -race'",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: golangci/golangci-lint-action@v6",
      "      - uses: golang/govulncheck-action@v1",
      "      - run: go test ./...",
    ].join("\n"),
  });
  assert.equal(safeGoWf.isPrBlocking, true);
  assert.ok(safeGoWf.activeCommands.includes("golangci-lint run"));
  assert.ok(safeGoWf.activeCommands.includes("govulncheck"));
  assert.ok(safeGoWf.activeCommands.some((c) => c.includes("go test")));

  const poisonedGoWf = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 9,
    content: [
      "on: [pull_request]",
      "env:",
      "  GOFLAGS: '-exec=/tmp/fake'",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: go test ./...",
    ].join("\n"),
  });
  assert.equal(poisonedGoWf.activeCommands.length, 0);
});

test("partitioned CI paths-ignore is accepted only when sibling PR workflow covers ignored paths", () => {
  const covered = makeTempRepo({
    "package.json": JSON.stringify({ name: "my-lib", exports: { ".": "./dist/index.js" }, scripts: { test: "vp test --run" } }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
    "src/index.test.ts": "import { test } from 'vitest'; import { add } from './index'; test('a', () => { if (add(1,2) !== 3) throw new Error(); });\n",
    ".github/workflows/ci.yml": [
      "on:",
      "  pull_request:",
      "    paths-ignore: ['adapters/**', 'docs/**', '.gitignore']",
      "jobs:",
      "  main:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
    ".github/workflows/ci-adapters.yml": [
      "on:",
      "  pull_request:",
      "    paths: ['adapters/**']",
      "jobs:",
      "  adapters:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
  });
  const uncovered = makeTempRepo({
    "package.json": JSON.stringify({ name: "my-lib", scripts: { test: "vitest run" } }),
    "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
    ".github/workflows/ci.yml": [
      "on:",
      "  pull_request:",
      "    paths-ignore: ['src/**']",
      "jobs:",
      "  main:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
  });
  try {
    const okRepo = discoverRepo(covered);
    assert.equal(okRepo.ci.hasCiWorkflows, true);
    assert.equal(okRepo.ci.runsUnitTests, true);

    const badRepo = discoverRepo(uncovered);
    assert.equal(badRepo.ci.hasCiWorkflows, false);
  } finally {
    fs.rmSync(covered, { recursive: true, force: true });
    fs.rmSync(uncovered, { recursive: true, force: true });
  }
});

test("CI shell-script expansion, Rust inline cfg(test), pure re-export facade crates, and scoped npm signals work accurately", () => {
  const pyDir = makeTempRepo({
    "pyproject.toml": '[project]\nname = "fastapi"\ndependencies = ["starlette>=1.0"]\n',
    "fastapi/applications.py": 'class FastAPI:\n    """app = FastAPI()"""\n    pass\n',
    "docs_src/tutorial001.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    "tests/test_app.py": "from fastapi.applications import FastAPI\ndef test_ok():\n    assert FastAPI is not None\n",
    "scripts/test-cov.sh": "#!/usr/bin/env bash\nbash scripts/test.sh\n",
    "scripts/test.sh": "#!/usr/bin/env bash\npytest tests\n",
    ".github/workflows/test.yml": [
      "on: [pull_request]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: uv run --no-sync bash scripts/test-cov.sh",
    ].join("\n"),
  });
  const rsDir = makeTempRepo({
    "Cargo.toml": '[workspace]\nmembers = ["crates/core", "crates/facade"]\n',
    "crates/core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\n',
    "crates/core/src/lib.rs": "pub fn double(x: i32) -> i32 { x * 2 }\n#[cfg(test)]\nmod tests {\n  use super::*;\n  #[test]\n  fn doubles() { assert_eq!(double(2), 4); }\n}\n",
    "crates/facade/Cargo.toml": '[package]\nname = "facade"\nversion = "0.1.0"\n',
    "crates/facade/src/lib.rs": "pub extern crate core as reexported;\n",
    "fuzz/Cargo.toml": '[package]\nname = "fuzz"\nversion = "0.1.0"\n',
    "fuzz/src/main.rs": "fn main() {}\n",
  });
  const goDir = makeTempRepo({
    "go.mod": "module example.com/demo\ngo 1.23\n",
    "main.go": "package demo\nfunc Add(a, b int) int { return a + b }\n",
    "main_test.go": [
      "package demo",
      'import ("runtime"; "testing")',
      "func TestCondSkip(t *testing.T) {",
      '  if runtime.GOOS != "linux" {',
      '    t.Skip("linux only")',
      "  }",
      "  if Add(1, 2) != 3 { t.Fatal(1) }",
      "}",
      "func TestUncondSkip(t *testing.T) {",
      '  t.Skip("broken")',
      "}",
    ].join("\n"),
  });
  const scopedDir = makeTempRepo({
    "package.json": JSON.stringify({
      name: "svc",
      dependencies: { express: "^5.0.0", "@sentry/node": "^10.0.0" },
      devDependencies: { "@electric-sql/pglite": "^0.5.0", "@stryker-mutator/core": "^9.0.0", vitest: "^4.0.0" },
      scripts: { test: "vitest run" },
    }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/app.ts": "export const ok = true;\n",
    "test/db/migrate.test.ts": "import { PGlite } from '@electric-sql/pglite'; import { test, expect } from 'vitest'; test('m', () => { expect(typeof PGlite).toBe('function'); });\n",
    ".github/workflows/ci.yml": "on: [pull_request]\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n",
  });
  try {
    const pyRepo = discoverRepo(pyDir);
    assert.equal(pyRepo.archetype, "library");
    assert.equal(pyRepo.ci.runsUnitTests, true);

    const rsReport = scanRepo(rsDir);
    assert.equal(rsReport.workspaces?.length, 1);
    assert.equal(rsReport.workspaces?.[0]?.path, "crates/core");
    assert.ok((rsReport.workspaces?.[0]?.score ?? 0) > 0);

    const goReport = scanRepo(goDir);
    const skips = goReport.findings.filter((f) => f.rule === "test-discipline");
    assert.equal(skips.length, 1);
    assert.equal(skips[0]?.line, 10);

    const scRepo = discoverRepo(scopedDir);
    assert.equal(scRepo.signals.hasProdTelemetryOrCanary, true);
    assert.equal(scRepo.signals.hasMigrationTest, true);
    assert.equal(scRepo.signals.hasMutationTool, true);
    assert.equal(scRepo.ci.runsIntegrationOrDbTests, true);
    assert.equal(scRepo.ci.runsBoundaryOrMbtTests, true);
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true });
    fs.rmSync(rsDir, { recursive: true, force: true });
    fs.rmSync(goDir, { recursive: true, force: true });
    fs.rmSync(scopedDir, { recursive: true, force: true });
  }
});
