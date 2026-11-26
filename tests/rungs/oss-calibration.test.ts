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

test("AI-first CI patterns: draft guard, parallel steps, benign git token rewrite, QML pragma, shell tests, and agent-doc symlinks", () => {
  const wfDraftAndParallel = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 22,
    content: [
      "on: [pull_request]",
      "env:",
      '  GIT_CONFIG_COUNT: "1"',
      "  GIT_CONFIG_KEY_0: url.https://x-access-token:${{ github.token }}@github.com/.insteadOf",
      "  GIT_CONFIG_VALUE_0: https://github.com/",
      "jobs:",
      "  check:",
      "    if: ${{ !github.event.pull_request.draft }}",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - parallel:",
      "          - name: Lint",
      "            run: pnpm biome ci",
      "          - name: Test",
      "            env:",
      "              MUTATION_TARGET: MutationTestsCore",
      "            shell: pwsh",
      "            run: ./build.ps1 -Target ${env:MUTATION_TARGET}",
    ].join("\n"),
  });
  assert.equal(wfDraftAndParallel.isPrBlocking, true);
  assert.ok(wfDraftAndParallel.activeCommands.some((c) => c.includes("biome ci")));
  assert.ok(wfDraftAndParallel.activeCommands.some((c) => c.includes("MutationTestsCore")));

  const wfBadGitConfig = parseGitHubWorkflow({
    abs: "/tmp/bad.yml",
    rel: ".github/workflows/bad.yml",
    isTest: false,
    isWorkflow: true,
    lines: 10,
    content: [
      "on: [pull_request]",
      "env:",
      '  GIT_CONFIG_COUNT: "1"',
      "  GIT_CONFIG_KEY_0: core.hooksPath",
      "  GIT_CONFIG_VALUE_0: /tmp/evil",
      "jobs:",
      "  t:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: bun test",
    ].join("\n"),
  });
  assert.equal(wfBadGitConfig.activeCommands.length, 0);

  const dir = makeTempRepo({
    "shell/ui.js": ".pragma library\nfunction fmt(x) { return String(x); }\n",
    "test/shell.d/proc-test.sh": "#!/usr/bin/env bash\npkill -f dummy\n",
    "bin/run.sh": "#!/usr/bin/env bash\necho ok\n",
    "AGENTS.md": "# Agent Rules\n",
    "web/docs/package.json": JSON.stringify({ name: "docs", dependencies: { astro: "^5.0.0" } }),
    "web/docs/src/Page.astro": "---\n---\n<div/>",
    "common/eslint-config/package.json": JSON.stringify({ name: "@org/eslint-config" }),
    "common/eslint-config/index.js": "export default [];\n",
    "samples/DemoApp/DemoApp.csproj": "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
    "samples/DemoApp/Program.cs": "var b = WebApplication.CreateBuilder(args);\n",
    "src/Core/Core.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
    "src/Core/Policy.cs": "namespace Core; public class Policy { public int Ok() => 1; }\n",
    "test/Core.Tests/Core.Tests.csproj": "<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup><ItemGroup><ProjectReference Include=\"..\\..\\src\\Core\\Core.csproj\" /></ItemGroup></Project>\n",
    "test/Core.Tests/PolicyTests.cs": "using Core; using Xunit; public class PolicyTests { [Fact] public void T() => Assert.Equal(1, new Policy().Ok()); }\n",
    ".github/workflows/agent-sweep.lock.yml": "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  sweep:\n    runs-on: ubuntu-latest\n    steps:\n      - continue-on-error: true\n        run: echo sweep\n",
  });
  fs.symlinkSync(path.join(dir, "AGENTS.md"), path.join(dir, "CLAUDE.md"));
  try {
    const rep = scanRepo(dir);
    assert.equal(rep.archetype, "library");
    assert.equal(rep.summary.excludedCount, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "ts-syntax-parse-error").length, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "sh-pkill-f-pattern-kill").length, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "ci-continue-on-error").length, 0);
    assert.equal(rep.workspaces?.length, 1);
    assert.equal(rep.workspaces?.[0]?.path, "src/Core");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
