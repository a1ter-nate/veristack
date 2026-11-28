import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildRatchetBaseline, createPluginHostSync, createState, formatTerminalReport, loadRungManifest, runCli, scanRepo } from "@veristack/core";

test("State.create tracks revision and createPluginHostSync activates all 18 built-in plugins", () => {
  const st = createState<number[], { push: (n: number) => void }>({
    name: "core.unit.nums",
    initial: () => [],
    editor: (draft) => ({ push: (n) => { draft.push(n); } }),
  });
  assert.equal(st.revision(), 0);
  const reg = st.transform((ed) => ed.push(42));
  assert.deepEqual(st.get(), [42]);
  assert.equal(st.revision(), 1);
  reg.dispose();
  assert.deepEqual(st.get(), []);

  const host = createPluginHostSync({ includeBuiltins: true });
  const entries = host.list();
  assert.equal(entries.length, 18);
  assert.equal(entries.every((e) => e.status === "active"), true);
});

test("buildRatchetBaseline includes dependenciesCount only when a numeric count is supplied", () => {
  const withDeps = buildRatchetBaseline([], undefined, 3);
  assert.equal(withDeps.dependenciesCount, 3);
  const withoutDeps = buildRatchetBaseline([]);
  assert.equal("dependenciesCount" in withoutDeps, false);
});

test("runCli rejects unknown flags with exit code 2 and honors init --dry-run without writing files", async () => {
  const badCode = await runCli(["scan", ".", "--totally-bogus-flag"]);
  assert.equal(badCode, 2);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cli-dryrun-"));
  try {
    fs.writeFileSync(path.join(dir, "app.ts"), "export const n = 1;\n");
    const initCode = await runCli(["init", dir, "--dry-run"]);
    assert.equal(initCode, 0);
    assert.deepEqual(fs.readdirSync(dir), ["app.ts"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("runCli supports --version and -V flags cleanly", async () => {
  assert.equal(await runCli(["--version"]), 0);
  assert.equal(await runCli(["-V"]), 0);
});

test("loadRungManifest collects all rung errors in one report and formatTerminalReport shows errors before warnings", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-multi-err-"));
  try {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "rungs.json"),
      JSON.stringify({
        schemaVersion: 1,
        archetype: "library",
        rungs: { R0: { command: "echo ok" }, R1: { command: "echo still-bad" } },
      }),
    );
    const loaded = loadRungManifest(dir, (rung, cmd) => (cmd.startsWith("echo") ? `bad ${rung}` : null));
    assert.ok(loaded.error?.includes("bad R0"));
    assert.ok(loaded.error?.includes("bad R1"));

    fs.rmSync(path.join(dir, ".verification"), { recursive: true, force: true });
    fs.writeFileSync(path.join(dir, "app.ts"), "export const x = 1;\n");
    fs.writeFileSync(path.join(dir, ".vstack.json"), JSON.stringify({ rules: { "no-comments": "error" } }));
    const strictReport = scanRepo(dir, { strict: true });
    assert.equal(strictReport.config?.monotonicStrengthenOnly, true);

    const manyWarns = Array.from({ length: 30 }, (_, i) => ({
      id: `W:${i}`, rule: "w-rule", category: "structure" as const, rung: "R1" as const,
      severity: "warn" as const, file: `src/f${i}.ts`, line: 1, message: `warn ${i}`, fix: "fix",
    }));
    const errFinding = {
      id: "E:1", rule: "e-rule", category: "cheat" as const, rung: "R0" as const,
      severity: "error" as const, file: "src/bad.ts", line: 9, message: "critical err", fix: "fix",
    };
    const out = formatTerminalReport({ ...strictReport, findings: [...manyWarns, errFinding] });
    assert.ok(out.includes("[ERROR] R0 e-rule src/bad.ts:9"));
    assert.ok(out.indexOf("[ERROR]") < out.indexOf("[WARN]"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("datastore-free service skips r4-migrations gap and manifest rung paths classify tests", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-nodatastore-"));
  try {
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests", "boundary"), { recursive: true });
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "stateless-svc", dependencies: { express: "^5.0.0" } }));
    fs.writeFileSync(path.join(dir, ".verification", "rungs.json"), JSON.stringify({
      schemaVersion: 1, archetype: "service",
      rungs: { R3: { command: "bun test tests/boundary/" } },
    }));
    fs.writeFileSync(path.join(dir, "src", "server.ts"), "export function ping(): string { return 'pong'; }\n");
    fs.writeFileSync(path.join(dir, "tests", "boundary", "ping.test.ts"), 'import { test, expect } from "bun:test";\ntest("p", () => expect(1).toBe(1));\n');
    const report = scanRepo(dir);
    const r4 = report.rungs.find((r) => r.rung === "R4");
    const migCheck = r4?.checks.find((c) => c.id === "r4-migrations");
    assert.equal(migCheck?.passed, true);
    assert.equal(migCheck?.detail, "no datastore");
    const r3 = report.rungs.find((r) => r.rung === "R3");
    assert.ok((r3?.observedCount ?? 0) >= 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
