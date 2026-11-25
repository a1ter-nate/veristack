import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../../src/ladder.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave2-"));
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

test("Wave 2 ecosystem guards catch duplicate SQL migrations, env template secrets, Docker CA, CSS overlays, Vue script lang, plugin import, LLM tuple, JSX smells, Worker redirect, and CI wave/cache save", () => {
  withTempRepo(
    {
      "tsconfig.json": '{"compilerOptions":{"strict":true}}\n',
      "migrations/0012_add_users.sql": "CREATE TABLE users (id INT);\n",
      "migrations/0012_add_orgs.sql": "CREATE TABLE orgs (id INT);\n",
      ".env.example": "FIREBASE_KEY=AIzaSyDummyLiveLikeKey1234567890abcd\n",
      "Dockerfile": "FROM node:22-slim\nRUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates\nCMD [\"node\", \"server.js\"]\n",
      "src/styles.css": ".lc { position: fixed; inset: 0; background: #000; }\n",
      "src/Widget.vue": "<template><div/></template>\n<script setup>\nconst x = 1;\n</script>\n",
      "src/plugin-loader.ts": "export async function loadPlugin(pluginPath: string): Promise<unknown> {\n  return import(pluginPath);\n}\n",
      "src/tools/schema.ts": "export function makeTool(z: { tuple: (a: unknown[]) => unknown }): unknown {\n  return z.tuple([]);\n}\n",
      "src/components/Page.tsx": 'export function Page(dummyData: string[]): string {\n  return "<a onClick={fn}>go</a><option selected>x</option>" + dummyData.join(",");\n}\n',
      "src/worker.ts": 'export async function handle(url: string): Promise<Response> {\n  return fetch(url, { redirect: "error", signal: AbortSignal.timeout(1000) });\n}\n',
      ".github/workflows/ci.yml": [
        "name: ci",
        "on: pull_request",
        "concurrency:",
        "  group: ci-${{ github.ref }}",
        "  cancel-in-progress: true",
        "jobs:",
        "  verify:",
        "    runs-on: ubuntu-latest",
        "    timeout-minutes: 15",
        "    steps:",
        "      - run: turbo run build test",
        "      - uses: actions/cache/save@v4",
        "        with:",
        "          path: ~/.cache",
        "          key: cache-${{ hashFiles('**/pnpm-lock.yaml') }}",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "migration-duplicate-prefix",
        "ci-no-real-key-in-env-example",
        "docker-node-missing-system-ca",
        "no-unscoped-fullscreen-overlay-class",
        "vue-require-script-lang-ts",
        "esm-dynamic-import-no-cache-bust",
        "llm-tool-schema-no-tuple",
        "ui-no-dummy-data-in-prod",
        "ui-anchor-without-href",
        "react-option-selected",
        "worker-unsupported-fetch-redirect",
        "ci-combined-build-test-wave",
        "ci-cache-save-unscoped-branch",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Wave 2 Rust guards catch OnceLock<Mutex<HashMap>>, std Mutex held across .await, and bit-exact float goldens", () => {
  withTempRepo(
    {
      "src/cache.rs": [
        "use std::collections::HashMap;",
        "use std::sync::{Mutex, OnceLock};",
        "static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();",
        "pub async fn fetch_item(m: &Mutex<u32>, fut: impl std::future::Future<Output = ()>) {",
        "    let _g = m.lock().unwrap();",
        "    fut.await;",
        "}",
      ].join("\n"),
      "tests/dsp_test.rs": [
        "use mycrate::dsp;",
        "#[test]",
        "fn golden_bits() {",
        "    assert_eq!(dsp(1.0_f32).to_bits(), 0x3f80_0000);",
        "}",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      assert.ok(rules.has("rust-async-mutex-read-cache"), `expected rust-async-mutex-read-cache, got [${[...rules].join(", ")}]`);
      assert.ok(rules.has("no-cross-platform-float-bit-golden"), `expected no-cross-platform-float-bit-golden, got [${[...rules].join(", ")}]`);
    },
  );
});
