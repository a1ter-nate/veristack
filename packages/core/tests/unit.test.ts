import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildRatchetBaseline, createPluginHostSync, createState, runCli } from "@veristack/core";

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
