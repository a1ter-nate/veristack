import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverRepo } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { auditDiffAntiEvasion } from "@veristack/plugin-control-plane";
import { auditLaws } from "@veristack/plugin-laws-formal";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-blackhole-"));
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

test("Black Hole catches cross-file cycles, wrapper-escaped sinks, cross-file DAO cache drift, and SSR mutable globals", () => {
  withTempRepo(
    {
      "src/a.ts": 'import { b } from "./b.ts"; export function a(): number { return b() + 1; }\n',
      "src/b.ts": 'import { a } from "./a.ts"; export function b(): number { return a() + 1; }\n',
      "src/sink-wrapper.ts": 'export function runShell(cmd: string): unknown { return eval(cmd); }\n',
      "src/handler.ts": [
        'import { runShell } from "./sink-wrapper.ts";',
        "export function handle(req: { body: { cmd: string } }): unknown {",
        "  return runShell(req.body.cmd);",
        "}",
      ].join("\n"),
      "src/user-cache.ts": [
        "const cache = new Map<string, string>();",
        "export function getUser(id: string): string | undefined { return cache.get(id); }",
        "export function invalidateUser(id: string): void { cache.delete(id); }",
      ].join("\n"),
      "src/user-writer.ts": [
        'import { getUser } from "./user-cache.ts";',
        "export function updateUser(db: { update: (id: string) => void }, id: string): void {",
        "  void getUser(id);",
        "  db.update(id);",
        "}",
      ].join("\n"),
      "app/routes/dashboard.ts": [
        "const perUserCache = new Map<string, string>();",
        "export async function loader(req: { userId: string }): Promise<string> {",
        '  perUserCache.set(req.userId, "secret");',
        '  return perUserCache.get(req.userId) ?? "";',
        "}",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "graph-circular-module-dependency",
        "graph-wrapper-escaped-sink",
        "graph-cross-file-dao-cache-drift",
        "arch-ssr-module-mutable-state",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Black Hole catches .NET middleware order, cross-file DI captive deps, Celery visibility, K8s informer mutation, Agent SSE/scrub, and Go/Shell replay escapes", () => {
  withTempRepo(
    {
      "Program.cs": [
        "var builder = WebApplication.CreateBuilder(args);",
        "builder.Services.AddScoped<OrderDbContext>();",
        "builder.Services.AddSingleton<OrderWorker>();",
        "var app = builder.Build();",
        "app.UseAuthorization();",
        "app.UseAuthentication();",
      ].join("\n"),
      "OrderWorker.cs": [
        "public sealed class OrderWorker {",
        "  public OrderWorker(OrderDbContext db) {}",
        "}",
      ].join("\n"),
      "tasks/celery_app.py": [
        "visibility_timeout = 300",
        "task_time_limit = 600",
        "acks_late = True",
      ].join("\n"),
      "pkg/controller/reconcile.go": [
        "package controller",
        "import \"strings\"",
        "func reconcile(lister interface{}, podErr error, s, prefix string) string {",
        "  pod, _ := lister.Lister().Get()",
        "  pod.Labels[\"a\"] = \"b\"",
        "  _, ok := podErr.(DialError)",
        "  _ = ok",
        "  if strings.HasPrefix(s, prefix) { return s[len(prefix)+1:] }",
        '  panic("unimplemented")',
        "}",
      ].join("\n"),
      "src/agent-stream.ts": [
        "const pendingCalls = new Map<string, () => void>();",
        "export function track(id: string, fn: () => void, secrets: string[], text: string): string {",
        "  pendingCalls.set(id, fn);",
        "  let out = text;",
        '  for (const s of secrets) { out = out.replaceAll(s, "[REDACTED]"); }',
        "  return out;",
        "}",
      ].join("\n"),
      "scripts/verify.sh": [
        "#!/usr/bin/env bash",
        'if [ -n "${OPENCODE_REQUIRE_DIGESTS:-}" ]; then echo on; fi',
      ].join("\n"),
      "src/lib.rs": "pub fn unfinished() -> i32 { todo!() }\n",
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "arch-dotnet-middleware-order",
        "arch-dotnet-di-captive-or-unvalidated-scope",
        "arch-celery-ack-visibility-invariant",
        "arch-k8s-informer-mutate-without-deepcopy",
        "arch-agent-sse-rpc-leak-and-scrub-order",
        "go-error-type-assert-not-as",
        "go-slice-len-plus-offset-oob",
        "no-unimplemented-panic-in-prod",
        "sh-boolean-env-nonzero-trap",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Black Hole immune gates enforce repo chokepoints, CI supply-chain hardening, anti-evasion diff cheats, and executable laws --verify", () => {
  withTempRepo(
    {
      ".verification/chokepoints.json": JSON.stringify({
        rules: [
          { pattern: "fetch", languages: ["typescript"], allowPaths: ["src/http-executor.ts"], replacement: "requestExecutor.send" },
        ],
      }),
      "src/http-executor.ts": "export async function send(u: string): Promise<Response> { return fetch(u, { signal: AbortSignal.timeout(3000) }); }\n",
      "src/caller.ts": "export async function load(u: string): Promise<Response> { return fetch(u, { signal: AbortSignal.timeout(3000) }); }\n",
      ".github/workflows/deploy.yml": [
        "name: Deploy",
        "on: [push]",
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: third-party/deploy-action@v2",
        "      - run: vercel deploy --prod",
      ].join("\n"),
      ".golangci.yml": "linters:\n  enable:\n    - govet\n",
      ".verification/laws/core.laws.json": JSON.stringify({
        laws: [{ id: "law-pass", invariant: "1+1=2", witnessRef: "tests/law.test.ts" }],
      }),
      "CODEOWNERS": "/.verification/laws/ @owner\n",
      "tests/law.test.ts": [
        'import assert from "node:assert/strict";',
        'import { test } from "node:test";',
        'test("law passes", () => { assert.equal(1 + 1, 2); });',
      ].join("\n"),
    },
    (dir) => {
      const report = scanRepo(dir);
      const rules = new Set(report.findings.map((f) => f.rule));
      assert.ok(rules.has("chokepoint-banned-primitive"));
      assert.ok(!report.findings.some((f) => f.rule === "chokepoint-banned-primitive" && f.file === "src/http-executor.ts"));
      assert.ok(rules.has("ci-missing-explicit-permissions"));
      assert.ok(rules.has("ci-unpinned-third-party-action"));
      assert.ok(rules.has("ci-checkout-missing-persist-creds-false"));
      assert.ok(rules.has("immune-go-missing-safety-linters"));

      const lawRes = auditLaws(discoverRepo(dir), { verify: true });
      assert.equal(lawRes.findings.length, 0);
      assert.equal(lawRes.verifiedBackends[0]?.status, "passed");
    },
  );

  const evasion = auditDiffAntiEvasion([
    { file: "src/app.ts", line: 10, kind: "add", raw: `// ${"@ts"}-ignore`, code: "" },
    { file: "pkg/s.go", line: 5, kind: "add", raw: "foo() //nolint", code: "foo()" },
    { file: "tsconfig.json", line: 4, kind: "add", raw: '  "strict": false,', code: '  "strict": false,' },
    { file: "tests/foo.test.ts", line: 12, kind: "del", raw: "assert.equal(a, b);", code: "assert.equal(a, b);" },
    { file: "tests/foo.test.ts", line: 13, kind: "del", raw: "assert.equal(c, d);", code: "assert.equal(c, d);" },
    { file: ".github/workflows/ci.yml", line: 20, kind: "del", raw: "      - run: vstack scan . --fail-on-cheats", code: "" },
  ]);
  const evasionRules = new Set(evasion.map((f) => f.rule));
  for (const expected of [
    "diff-ts-suppression-added",
    "diff-go-nolint-added",
    "diff-config-strictness-downgrade",
    "diff-assertion-deleted",
    "diff-ci-safety-gate-removed",
  ]) {
    assert.ok(evasionRules.has(expected), `expected ${expected}, got [${[...evasionRules].join(", ")}]`);
  }
});

test("Black Hole catches T3 Code / pingdotgg / t3-oss immune rules (test frame/polling/loop/timeout, pkill -f, Drizzle tz)", () => {
  withTempRepo(
    {
      "scripts/kill.sh": "#!/usr/bin/env bash\npkill -f vite\n",
      "src/schema.ts": 'import { pgTable, timestamp } from "drizzle-orm/pg-core";\nexport const t = pgTable("t", { createdAt: timestamp("created_at") });\n',
      "tests/flaky.test.ts": [
        'import { it, expect } from "vitest";',
        'for (const n of [1, 2]) {',
        '  it("looped", () => { expect(n).toBe(n); });',
        "}",
        'it("slow", async () => {',
        "  requestAnimationFrame(() => {});",
        "  while (true) { await sleep(10); break; }",
        "}, 30000);",
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "sh-pkill-f-pattern-kill",
        "drizzle-timestamp-missing-timezone",
        "test-no-test-in-loop",
        "test-no-frame-waits",
        "test-no-polling-loop",
        "test-no-per-test-timeout",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});
