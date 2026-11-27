import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createPluginHost } from "@veristack/core";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEMO_PLUGIN_DIR = path.join(REPO_ROOT, "examples", "plugins", "demo-todo-guard");
const CLI_ENTRY = path.join(REPO_ROOT, "src", "cli.ts");

function withFixtureRepo(fn: (dir: string) => Promise<void> | void): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-demo-toggle-"));
  fs.mkdirSync(path.join(dir, "src"), { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "toggle-fixture", version: "1.0.0" }, null, 2));
  fs.writeFileSync(path.join(dir, "src", "app.ts"), 'export const note = "FIXME_BLOCKER: replace before release";\n');
  fs.writeFileSync(path.join(dir, "src", "rules.vdsl"), "rule alpha { FIXME_BLOCKER }\n");
  return Promise.resolve(fn(dir)).finally(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
}

describe("Standalone Third-Party Reference Plugin ON/OFF Toggle", () => {
  test("programmatic host toggle ON activates custom language/rule and toggle OFF leaves zero residue while preserving guarded plugins", async () => {
    await withFixtureRepo(async (fixtureDir) => {
      const hostOn = await createPluginHost({
        repoDir: fixtureDir,
        includeBuiltins: true,
        operations: [{ type: "add", target: DEMO_PLUGIN_DIR }],
      });
      try {
        const activeList = hostOn.list();
        const demoEntry = activeList.find((p) => p.id === "demo.plugin.todo-guard");
        assert.ok(demoEntry);
        assert.equal(demoEntry.status, "active");

        const scanOn = await hostOn.scan(fixtureDir);
        const demoFindingsOn = scanOn.findings.filter((f) => f.rule === "demo-todo-guard");
        assert.equal(demoFindingsOn.length, 2);
        assert.equal(scanOn.languages.includes("demo-dsl"), true);
        assert.ok(hostOn.registries.commands().some((c) => c.name === "demo-status"));
      } finally {
        await hostOn.dispose();
      }

      const hostOff = await createPluginHost({
        repoDir: fixtureDir,
        includeBuiltins: true,
        operations: [
          { type: "add", target: DEMO_PLUGIN_DIR },
          { type: "remove", target: "demo.plugin.todo-guard" },
        ],
      });
      try {
        assert.equal(hostOff.list().some((p) => p.id === "demo.plugin.todo-guard"), false);
        const scanOff = await hostOff.scan(fixtureDir);
        assert.equal(scanOff.findings.some((f) => f.rule === "demo-todo-guard"), false);
        assert.equal(scanOff.languages.includes("demo-dsl"), false);
        assert.equal(hostOff.registries.commands().some((c) => c.name === "demo-status"), false);

        const guardedActive = hostOff.list().filter((p) => p.guarded && p.status === "active");
        assert.ok(guardedActive.length >= 1);
      } finally {
        await hostOff.dispose();
      }
    });
  });

  test("CLI 2-command ON/OFF toggle works end-to-end via --plugin and --disable-plugin", async () => {
    await withFixtureRepo((fixtureDir) => {
      const onCmd = spawnSync(
        "bun",
        [CLI_ENTRY, "scan", fixtureDir, "--allow-missing-rungs", "--json", "--plugin", DEMO_PLUGIN_DIR],
        { encoding: "utf8" },
      );
      assert.equal(onCmd.status, 0, onCmd.stderr);
      const onReport = JSON.parse(onCmd.stdout) as { findings: Array<{ rule: string }>; languages: string[] };
      assert.equal(onReport.findings.filter((f) => f.rule === "demo-todo-guard").length, 2);
      assert.equal(onReport.languages.includes("demo-dsl"), true);

      const statusCmd = spawnSync("bun", [CLI_ENTRY, "demo-status", "--json", "--plugin", DEMO_PLUGIN_DIR], {
        encoding: "utf8",
      });
      assert.equal(statusCmd.status, 0, statusCmd.stderr);
      const statusPayload = JSON.parse(statusCmd.stdout) as { plugin: string; active: boolean };
      assert.equal(statusPayload.plugin, "demo.plugin.todo-guard");
      assert.equal(statusPayload.active, true);

      const offCmd = spawnSync(
        "bun",
        [
          CLI_ENTRY,
          "scan",
          fixtureDir,
          "--allow-missing-rungs",
          "--json",
          "--plugin",
          DEMO_PLUGIN_DIR,
          "--disable-plugin",
          "demo.plugin.todo-guard",
        ],
        { encoding: "utf8" },
      );
      assert.equal(offCmd.status, 0, offCmd.stderr);
      const offReport = JSON.parse(offCmd.stdout) as { findings: Array<{ rule: string }>; languages: string[] };
      assert.equal(offReport.findings.some((f) => f.rule === "demo-todo-guard"), false);
      assert.equal(offReport.languages.includes("demo-dsl"), false);
    });
  });
});
