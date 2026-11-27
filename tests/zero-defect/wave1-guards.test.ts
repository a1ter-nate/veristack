import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import { scanRepo } from "@veristack/core";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave1-"));
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

test("CI workflow rules catch two-dot PR diffs, always() without gate check, unbounded workers, static ports, unbuilt browser jobs, missing cache hashes, and Maestro unsafe scroll", () => {
  withTempRepo(
    {
      ".github/workflows/ci.yml": [
        "name: ci",
        "on: pull_request",
        "concurrency:",
        "  group: ci-${{ github.ref }}",
        "  cancel-in-progress: true",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 15",
        "    steps:",
        "      - uses: actions/cache@v4",
        "        with:",
        "          path: ~/.cache",
        "          key: static-cache-key",
        "      - run: git diff --name-only $BASE_SHA $HEAD_SHA",
        "      - run: pnpm vitest run --maxWorkers=12 &",
        "      - run: npx vite preview --port 4175",
        "  e2e:",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 15",
        "    steps:",
        "      - run: npx playwright test",
        "  publish:",
        "    needs: [test]",
        "    if: always()",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 10",
        "    steps:",
        "      - run: echo publishing",
      ].join("\n"),
      "e2e/mobile/login.yaml": [
        "appId: com.example.app",
        "---",
        "- scrollUntilVisible:",
        "    element: submit-btn",
        "    direction: DOWN",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "ci-two-dot-pr-diff",
        "ci-unbounded-test-workers",
        "ci-hardcoded-service-port",
        "ci-cache-key-missing-hash",
        "ci-always-without-gate-check",
        "ci-unbuilt-browser-consumer",
        "e2e-maestro-unsafe-scroll",
      ]) {
        assert.ok(rules.has(expected), `expected rule ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Test harness guards catch missing emulator guard, vi.mock hoist hazard, repo-root mutation, and DAO mocking with fake DB", () => {
  withTempRepo(
    {
      "tests/emulator.setup.ts": 'export const host = process.env.FIRESTORE_EMULATOR_HOST ?? "localhost";\n',
      "tests/bad-harness.test.ts": [
        'import { test, expect, vi } from "vitest";',
        'import admin from "firebase-admin";',
        'import fs from "node:fs";',
        'import path from "node:path";',
        "const fakeDb = { get: () => null };",
        'vi.mock("../../src/dao/orders", () => ({ db: fakeDb }));',
        'test("writes repo", () => {',
        '  fs.writeFileSync(path.join(process.cwd(), "src/tmp.txt"), "x");',
        "  expect(admin.apps.length).toBe(0);",
        "});",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "no-dao-mock-with-fake-db",
        "test-repo-mutation-risk",
        "vitest-mock-hoist-hazard",
      ]) {
        assert.ok(rules.has(expected), `expected rule ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );

  withTempRepo(
    {
      "tests/live-cloud.test.ts": [
        'import { test, expect } from "vitest";',
        'import { initializeApp } from "firebase-admin/app";',
        'test("hits cloud", () => {',
        "  const app = initializeApp();",
        "  expect(app.name).toBe('[DEFAULT]');",
        "});",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      assert.ok(rules.has("test-require-emulator-guard"), `expected test-require-emulator-guard, got [${[...rules].join(", ")}]`);
    },
  );
});

test("async-effect-stale-guard and no-unbounded-batch-write fire on broken patterns and stay clean when guarded", () => {
  withTempRepo(
    {
      "src/bad-ui.tsx": [
        "export function Panel(useEffect: (fn: () => void) => void, fetchItem: () => Promise<string>, setItem: (v: string) => void): void {",
        "  useEffect(() => {",
        "    async function load() {",
        "      const data = await fetchItem();",
        "      setItem(data);",
        "    }",
        "    void load();",
        "  });",
        "}",
      ].join("\n"),
      "src/bad-batch.ts": [
        "export function writeAll(batch: { set: (k: string, v: number) => void }, rows: number[]): void {",
        "  for (let i = 0; i < rows.length; i++) {",
        "    batch.set(String(i), rows[i] ?? 0);",
        "  }",
        "}",
      ].join("\n"),
      "src/clean-ui.tsx": [
        "export function SafePanel(useEffect: (fn: () => () => void) => void, fetchItem: (s: AbortSignal) => Promise<string>, setItem: (v: string) => void): void {",
        "  useEffect(() => {",
        "    const controller = new AbortController();",
        "    async function load() {",
        "      const data = await fetchItem(controller.signal);",
        "      if (!controller.signal.aborted) setItem(data);",
        "    }",
        "    void load();",
        "    return () => controller.abort();",
        "  });",
        "}",
      ].join("\n"),
    },
    (dir) => {
      const report = scanRepo(dir);
      const badUiRules = report.findings.filter((f) => f.file === "src/bad-ui.tsx").map((f) => f.rule);
      const badBatchRules = report.findings.filter((f) => f.file === "src/bad-batch.ts").map((f) => f.rule);
      const cleanUiRules = report.findings.filter((f) => f.file === "src/clean-ui.tsx").map((f) => f.rule);
      assert.ok(badUiRules.includes("async-effect-stale-guard"));
      assert.ok(badBatchRules.includes("no-unbounded-batch-write"));
      assert.deepEqual(cleanUiRules, []);
    },
  );
});

test("diff-ts-skipped-test catches added test.skip in git diffs and contractChecks detects stale OpenAPI/index drift", () => {
  withTempRepo(
    {
      "src/routes.ts": "export const version = 1;\n",
      "docs/openapi.json": "{}\n",
      "tests/api.test.ts": 'import { test } from "vitest";\ntest("ok", () => {});\n',
    },
    (dir) => {
      const git = (...args: string[]) => spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
      git("init");
      git("config", "user.email", "test@example.com");
      git("config", "user.name", "Test");
      git("add", ".");
      git("commit", "-m", "init");
      const baseSha = git("rev-parse", "HEAD").stdout.trim();

      fs.writeFileSync(path.join(dir, "src/routes.ts"), "export const version = 2;\n", "utf8");
      fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
      fs.writeFileSync(
        path.join(dir, ".verification/control-plan.json"),
        JSON.stringify({
          contractChecks: [
            { id: "openapi", artifactFile: "docs/openapi.json", coveredPaths: ["src/routes.ts"], syncCommit: baseSha },
          ],
        }),
        "utf8",
      );
      git("add", ".");
      git("commit", "-m", "change routes without updating openapi");

      const scan = scanRepo(dir);
      assert.ok(
        scan.findings.some((f) => f.rule === "contract-artifact-stale"),
        "expected contract-artifact-stale when routes changed after syncCommit",
      );

      fs.writeFileSync(
        path.join(dir, "tests/api.test.ts"),
        'import { test } from "vitest";\ntest.skip("flaky", () => {});\n',
        "utf8",
      );
      const diffFindings = scanGitDiffCheats(dir, "HEAD");
      assert.ok(
        diffFindings.some((f) => f.rule === "diff-ts-skipped-test"),
        "expected diff-ts-skipped-test on added test.skip",
      );
    },
  );
});
