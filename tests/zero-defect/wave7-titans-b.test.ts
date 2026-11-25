import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../../src/ladder.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-wave7-"));
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

test("Wave 7 catches RLS fail-open policies, auth GET missing no-store, runner fake-timer capture, and shell test-lib ordering/sockpath", () => {
  withTempRepo(
    {
      "supabase/policies/items.sql": [
        "CREATE POLICY items_write ON items FOR UPDATE USING (true);",
        "CREATE FUNCTION admin_op() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1; $$;",
      ].join("\n"),
      "src/routes/auth-session.ts": [
        "export function mount(app: { get: (p: string, fn: () => unknown) => void }): void {",
        '  app.get("/api/auth/session", () => ({ user: "alice" }));',
        "}",
      ].join("\n"),
      "src/test-runner.ts": [
        "export function scheduleWatchdog(cb: () => void): void {",
        "  setTimeout(cb, 5000);",
        "}",
      ].join("\n"),
      "t/t0001-basic.sh": [
        "#!/bin/sh",
        ". ./test-lib.sh",
        "TEST_DIRECTORY=/tmp/custom",
        'SOCK="$TRASH_DIRECTORY/daemon.sock"',
      ].join("\n"),
    },
    (dir) => {
      const rules = new Set(scanRepo(dir).findings.map((f) => f.rule));
      for (const expected of [
        "rls-fail-open-null-or-public-role",
        "auth-get-missing-no-store",
        "runner-capture-timer-globals",
        "shell-harness-order-and-sockpath",
      ]) {
        assert.ok(rules.has(expected), `expected ${expected}, got [${[...rules].join(", ")}]`);
      }
    },
  );
});

test("Wave 7 allows hardened RLS, no-store auth GET, captured timers, and clean shell harness", () => {
  withTempRepo(
    {
      "supabase/policies/items.sql": [
        "CREATE POLICY items_write ON items FOR UPDATE TO authenticated USING (auth.uid() = owner_id);",
        "CREATE FUNCTION admin_op() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT 1; $$;",
      ].join("\n"),
      "src/routes/auth-session.ts": [
        "export function mount(app: { get: (p: string, fn: () => unknown) => void }): void {",
        '  app.get("/api/auth/session", () => ({ headers: { "Cache-Control": "no-store" } }));',
        "}",
      ].join("\n"),
      "src/test-runner.ts": [
        "const nativeSetTimeout = globalThis.setTimeout;",
        "export function scheduleWatchdog(cb: () => void): void {",
        "  nativeSetTimeout(cb, 5000);",
        "}",
      ].join("\n"),
      "t/t0001-basic.sh": [
        "#!/bin/sh",
        "TEST_DIRECTORY=/tmp/custom",
        ". ./test-lib.sh",
        'SOCK="$(mktemp -d /tmp/sock.XXXXXX)/d.sock"',
      ].join("\n"),
    },
    (dir) => {
      const w7 = scanRepo(dir).findings.filter((f) => f.id.startsWith("W7:"));
      assert.equal(w7.length, 0, `unexpected W7 findings: ${w7.map((f) => f.rule).join(", ")}`);
    },
  );
});
