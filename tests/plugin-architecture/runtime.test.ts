import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import {
  loadVeristackPluginRuntime,
  readPluginStatus,
  VERISTACK_ROOT,
  type LoadedVeristackRuntime,
} from "./contract.ts";

function writeFiles(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
}

function requireRuntime(rt: LoadedVeristackRuntime | null): LoadedVeristackRuntime {
  assert.ok(rt !== null, "Missing @veristack/plugin or @veristack/core plugin host runtime");
  return rt;
}

describe("Veristack Behavioral Conformance: Replayable State, Composition, Guarded Anti-Cheat & Speed", () => {
  let tmpRoot = "";
  let sampleRepo = "";
  let rt: LoadedVeristackRuntime | null = null;

  before(async () => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "veristack-plugin-arch-"));
    sampleRepo = path.join(tmpRoot, "sample");
    writeFiles(sampleRepo, {
      "package.json": JSON.stringify({ name: "vstack-fixture", version: "1.0.0" }, null, 2),
      "src/app.ts": [
        "export function risky(input: unknown): number {",
        "  try {",
        "    return (input as any).count;",
        "  } catch {}",
        "  return 0;",
        "}",
      ].join("\n"),
      "crates/core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\nedition = "2021"\n',
      "crates/core/src/lib.rs": [
        "pub fn dangerous(v: Option<i32>) -> i32 {",
        "    v.unwrap()",
        "}",
      ].join("\n"),
      "src/custom.zig": "pub fn main() void {}\n",
    });
    rt = await loadVeristackPluginRuntime();
  });

  after(() => {
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  test("Law 5: Replayable State replays cleanly on disposal without mutating earlier snapshots", () => {
    const runtime = requireRuntime(rt);
    const state = runtime.createState<string[], { add: (v: string) => void; remove: (v: string) => void }>({
      name: "test.rules",
      initial: () => [],
      editor: (draft) => ({
        add: (v) => draft.push(v),
        remove: (v) => {
          const idx = draft.indexOf(v);
          if (idx >= 0) draft.splice(idx, 1);
        },
      }),
    });

    const empty = state.get();
    assert.deepEqual(empty, []);

    const regA = state.transform((e) => e.add("rule-a")) as { dispose?: () => void };
    const regB = state.transform((e) => e.add("rule-b")) as { dispose?: () => void };
    const both = state.get();
    assert.deepEqual(both, ["rule-a", "rule-b"]);
    assert.deepEqual(empty, []);

    if (typeof regA?.dispose === "function") regA.dispose();
    assert.deepEqual(state.get(), ["rule-b"]);
    assert.deepEqual(both, ["rule-a", "rule-b"]);
    if (typeof regB?.dispose === "function") regB.dispose();
  });

  test("Law 5b: Removing a non-guarded built-in language plugin cleanly removes its findings while preserving other packs", async () => {
    const runtime = requireRuntime(rt);
    const fullHost = await runtime.createPluginHost({ repoDir: sampleRepo, includeBuiltins: true });
    try {
      const plugins = await fullHost.list();
      const rustPlugin = plugins.find((p) => p.id.includes("rust") && readPluginStatus(p) === "active");
      assert.ok(rustPlugin, "Expected an active dogfooded Rust built-in plugin");

      const fullScan = await fullHost.scan(sampleRepo);
      assert.ok(fullScan.findings.some((f) => f.file.endsWith(".rs")));

      const noRustHost = await runtime.createPluginHost({
        repoDir: sampleRepo,
        includeBuiltins: true,
        operations: [{ type: "remove", target: rustPlugin.id }],
      });
      try {
        const reduced = await noRustHost.scan(sampleRepo);
        assert.equal(reduced.findings.some((f) => f.file.endsWith(".rs")), false);
        assert.equal(reduced.findings.some((f) => f.file.endsWith(".ts")), true);
      } finally {
        await noRustHost.dispose();
      }
    } finally {
      await fullHost.dispose();
    }
  });

  test("Law 6: Two external plugins compose across custom languages, analyzers, harnesses, and commands", async () => {
    const runtime = requireRuntime(rt);

    const zigPlugin = runtime.definePlugin({
      id: "acme.plugin.zig",
      async setup(ctx) {
        await ctx.language.transform((ed) => {
          ed.add({ id: "zig", extensions: [".zig"] });
        });
        await ctx.analyzer.transform((ed) => {
          ed.add({
            id: "acme.zig.check",
            run: () => [
              {
                id: "ACME:zig:src/custom.zig:1",
                rule: "acme-zig-policy",
                category: "structure",
                rung: "R1",
                severity: "warn",
                file: "src/custom.zig",
                line: 1,
                message: "Zig plugin finding",
                fix: "Apply Zig policy",
              },
            ],
          });
        });
      },
    });

    const harnessPlugin = runtime.definePlugin({
      id: "acme.plugin.harness",
      async setup(ctx) {
        await ctx.harness.transform((ed) => {
          ed.add({ id: "opencode", label: "OpenCode" });
        });
        await ctx.analyzer.transform((ed) => {
          ed.add({
            id: "acme.harness.check",
            run: () => [
              {
                id: "ACME:harness:src/app.ts:1",
                rule: "acme-harness-policy",
                category: "oracle-lock",
                rung: "R0",
                severity: "warn",
                file: "src/app.ts",
                line: 1,
                message: "Harness plugin finding",
                fix: "Wire harness",
              },
            ],
          });
        });
      },
    });

    const host = await runtime.createPluginHost({
      repoDir: sampleRepo,
      includeBuiltins: true,
      plugins: [zigPlugin, harnessPlugin],
    });
    try {
      const scanRes = await host.scan(sampleRepo);
      const rules = new Set(scanRes.findings.map((f) => f.rule));
      assert.equal(rules.has("acme-zig-policy"), true);
      assert.equal(rules.has("acme-harness-policy"), true);
      assert.equal(scanRes.languages.includes("zig"), true);
    } finally {
      await host.dispose();
    }
  });

  test("Law 7: Fault isolation detaches throwing plugin across all domains and guarded anti-cheat plugins survive remove:*", async () => {
    const runtime = requireRuntime(rt);

    const faulty = runtime.definePlugin({
      id: "acme.plugin.faulty",
      async setup(ctx) {
        await ctx.analyzer.transform((ed) => {
          ed.add({
            id: "acme.faulty.analyzer",
            run: () => [
              {
                id: "BAD:1",
                rule: "should-be-detached",
                category: "structure",
                rung: "R0",
                severity: "warn",
                file: "src/app.ts",
                line: 1,
                message: "Detached finding",
                fix: "None",
              },
            ],
          });
        });
        await ctx.command.transform(() => {
          throw new Error("simulated Veristack plugin crash");
        });
      },
    });

    const healthy = runtime.definePlugin({
      id: "acme.plugin.healthy",
      async setup(ctx) {
        await ctx.analyzer.transform((ed) => {
          ed.add({
            id: "acme.healthy.analyzer",
            run: () => [
              {
                id: "GOOD:1",
                rule: "healthy-plugin-rule",
                category: "structure",
                rung: "R0",
                severity: "warn",
                file: "src/app.ts",
                line: 1,
                message: "Healthy finding",
                fix: "None",
              },
            ],
          });
        });
      },
    });

    const host = await runtime.createPluginHost({
      repoDir: sampleRepo,
      includeBuiltins: true,
      plugins: [faulty, healthy],
    });
    try {
      const scanRes = await host.scan(sampleRepo);
      const rules = new Set(scanRes.findings.map((f) => f.rule));
      assert.equal(rules.has("healthy-plugin-rule"), true);
      assert.equal(rules.has("should-be-detached"), false);

      const statuses = await host.list();
      const faultyEntry = statuses.find((s) => s.id === "acme.plugin.faulty");
      assert.ok(faultyEntry);
      assert.equal(readPluginStatus(faultyEntry), "failed");
    } finally {
      await host.dispose();
    }

    const lockHost = await runtime.createPluginHost({
      repoDir: sampleRepo,
      includeBuiltins: true,
      operations: [{ type: "remove", target: "*" }],
    });
    try {
      const remaining = await lockHost.list();
      const activeGuarded = remaining.filter((p) => p.guarded === true && readPluginStatus(p) === "active");
      assert.ok(activeGuarded.length >= 1, "Guarded control-plane / anti-cheat plugins must survive remove:*");
    } finally {
      await lockHost.dispose();
    }
  });

  test("Law 8: External package plugins load via package.json exports cleanly", async () => {
    const runtime = requireRuntime(rt);
    const extDir = path.join(tmpRoot, "ext-vstack-plugin");
    const sdkAbs = path.join(VERISTACK_ROOT, "packages/plugin/src/index.ts");
    writeFiles(extDir, {
      "package.json": JSON.stringify(
        {
          name: "veristack-plugin-ext-test",
          version: "1.0.0",
          type: "module",
          exports: { ".": "./index.ts" },
        },
        null,
        2,
      ),
      "index.ts": [
        `import { Plugin } from ${JSON.stringify(sdkAbs)};`,
        "export default Plugin.define({",
        '  id: "ext.vstack.pkg",',
        "  async setup(ctx) {",
        "    await ctx.analyzer.transform((ed) => {",
        "      ed.add({",
        '        id: "ext.vstack.analyzer",',
        "        run: () => [{",
        '          id: "EXT:1",',
        '          rule: "ext-pkg-rule",',
        '          category: "structure",',
        '          rung: "R1",',
        '          severity: "warn",',
        '          file: "src/app.ts",',
        "          line: 1,",
        '          message: "Loaded from external package",',
        '          fix: "Fix it",',
        "        }],",
        "      });",
        "    });",
        "  },",
        "});",
      ].join("\n"),
    });

    const host = await runtime.createPluginHost({
      repoDir: sampleRepo,
      includeBuiltins: true,
      operations: [{ type: "add", target: extDir }],
    });
    try {
      const statuses = await host.list();
      const loaded = statuses.find((s) => s.id === "ext.vstack.pkg");
      assert.ok(loaded);
      assert.equal(readPluginStatus(loaded), "active");
      const scanRes = await host.scan(sampleRepo);
      assert.equal(scanRes.findings.some((f) => f.rule === "ext-pkg-rule"), true);
    } finally {
      await host.dispose();
    }
  });
});
