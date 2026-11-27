import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { auditDirectory, resolveRelativeImport, VERISTACK_ROOT } from "./contract.ts";

const BUILTIN_MANIFEST_ALLOWLIST = new Set([
  "packages/core/src/plugin/internal.ts",
  "packages/core/src/builtins.ts",
]);

const REQUIRED_PLUGIN_GROUPS = [
  "lang-typescript",
  "lang-csharp",
  "lang-rust",
  "lang-python",
  "lang-go",
  "anti-slop",
  "tigerstyle",
  "effect-v4",
  "zero-defect",
  "state-machines",
  "agent-docs",
  "ci-auditor",
  "review-brief",
  "canary",
  "laws-formal",
  "harnesses",
  "circuits",
  "control-plane",
] as const;

const REQUIRED_DOMAINS = [
  "language",
  "signal",
  "analyzer",
  "rung",
  "harness",
  "circuit",
  "provider",
  "reporter",
  "command",
] as const;

const MAX_CORE_KERNEL_LINES = 6_500;
const MAX_LEGACY_SRC_LINES = 500;

interface RootPkgJson {
  workspaces?: string[] | { packages?: string[] };
  exports?: Record<string, string>;
  dependencies?: Record<string, string>;
}

function readRootPackageJson(): RootPkgJson {
  return JSON.parse(fs.readFileSync(path.join(VERISTACK_ROOT, "package.json"), "utf8")) as RootPkgJson;
}

function listWorkspacePackageDirs(): string[] {
  const pkgRoot = path.join(VERISTACK_ROOT, "packages");
  if (!fs.existsSync(pkgRoot)) return [];
  const dirs: string[] = [];
  for (const entry of fs.readdirSync(pkgRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name === "plugins") {
      const pluginsRoot = path.join(pkgRoot, "plugins");
      for (const sub of fs.readdirSync(pluginsRoot, { withFileTypes: true })) {
        if (sub.isDirectory()) dirs.push(`packages/plugins/${sub.name}`);
      }
    } else {
      dirs.push(`packages/${entry.name}`);
    }
  }
  return dirs.sort();
}

function listPluginSubdirs(): string[] {
  const pluginsRoot = path.join(VERISTACK_ROOT, "packages/plugins");
  if (!fs.existsSync(pluginsRoot)) return [];
  return fs
    .readdirSync(pluginsRoot, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

describe("Law 1: Tight Core & Real Package Boundary (No Barrel Illusion)", () => {
  test("dedicated packages/plugin and packages/core exist and are exported from root package.json", () => {
    const pkgJson = readRootPackageJson();
    assert.equal(fs.existsSync(path.join(VERISTACK_ROOT, "packages/plugin/package.json")), true);
    assert.equal(fs.existsSync(path.join(VERISTACK_ROOT, "packages/plugin/src/index.ts")), true);
    assert.equal(fs.existsSync(path.join(VERISTACK_ROOT, "packages/core/package.json")), true);
    assert.equal(fs.existsSync(path.join(VERISTACK_ROOT, "packages/core/src/index.ts")), true);
    assert.ok(pkgJson.exports?.["./plugin"], "package.json exports must expose ./plugin");
    assert.ok(pkgJson.exports?.["./core"], "package.json exports must expose ./core");
  });

  test("no package under packages/* reaches backward into legacy src/**", () => {
    const pkgDirs = listWorkspacePackageDirs();
    assert.ok(pkgDirs.length >= 2, "Expected packages/core and packages/plugin workspace packages");
    const violations: string[] = [];
    for (const pkgDir of pkgDirs) {
      const audit = auditDirectory(VERISTACK_ROOT, pkgDir);
      for (const edge of audit.imports) {
        const resolved = resolveRelativeImport(edge.fromRel, edge.specifier);
        if (resolved === "src" || resolved?.startsWith("src/")) {
          violations.push(`${edge.fromRel}:${edge.line} imports legacy monolith "${edge.specifier}"`);
        }
      }
    }
    assert.deepEqual(violations, []);
  });

  test("core kernel does not import feature plugins outside the single built-in manifest", () => {
    const coreAudit = auditDirectory(VERISTACK_ROOT, "packages/core/src");
    assert.ok(coreAudit.files.length > 0, "Expected core source files under packages/core/src");
    const violations: string[] = [];
    for (const edge of coreAudit.imports) {
      if (BUILTIN_MANIFEST_ALLOWLIST.has(edge.fromRel)) continue;
      const resolved = resolveRelativeImport(edge.fromRel, edge.specifier);
      const importsFeature =
        resolved?.startsWith("packages/plugins/") || edge.specifier.startsWith("@veristack/plugin-");
      if (importsFeature) {
        violations.push(`${edge.fromRel}:${edge.line} imports feature plugin "${edge.specifier}"`);
      }
    }
    assert.deepEqual(violations, []);
  });

  test("packages/plugin SDK has zero upward imports from packages/core or packages/plugins", () => {
    const sdkAudit = auditDirectory(VERISTACK_ROOT, "packages/plugin/src");
    assert.ok(sdkAudit.files.length > 0, "Expected SDK files under packages/plugin/src");
    const violations: string[] = [];
    for (const edge of sdkAudit.imports) {
      const resolved = resolveRelativeImport(edge.fromRel, edge.specifier);
      const target = resolved ?? edge.specifier;
      if (
        target.startsWith("packages/core") ||
        target.startsWith("packages/plugins") ||
        target.startsWith("@veristack/core") ||
        target.startsWith("@veristack/plugin-")
      ) {
        violations.push(`${edge.fromRel}:${edge.line} leaks upward dependency "${edge.specifier}"`);
      }
    }
    assert.deepEqual(violations, []);
  });
});

describe("Law 2: Dogfooded Built-In Plugins (Zero Privileged Backdoors)", () => {
  test("packages/plugins/* workspace holds dogfooded first-party plugins for every major capability", () => {
    const pkgJson = readRootPackageJson();
    const workspaces = Array.isArray(pkgJson.workspaces)
      ? pkgJson.workspaces
      : (pkgJson.workspaces?.packages ?? []);
    assert.ok(workspaces.includes("packages/plugins/*"), "package.json workspaces must include packages/plugins/*");

    const present = listPluginSubdirs();
    const missing = REQUIRED_PLUGIN_GROUPS.filter(
      (req) => !present.some((dir) => dir === req || dir.includes(req)),
    );
    assert.deepEqual(missing, []);
  });

  test("built-in plugins under packages/plugins/* never import packages/core internals or legacy src/**", () => {
    const pluginsAudit = auditDirectory(VERISTACK_ROOT, "packages/plugins");
    assert.ok(pluginsAudit.files.length >= REQUIRED_PLUGIN_GROUPS.length);
    const violations: string[] = [];
    for (const edge of pluginsAudit.imports) {
      const resolved = resolveRelativeImport(edge.fromRel, edge.specifier);
      const target = resolved ?? edge.specifier;
      if (
        target.startsWith("packages/core/src/internal") ||
        target.startsWith("src/") ||
        target.includes("/core/src/internal")
      ) {
        violations.push(`${edge.fromRel}:${edge.line} bypasses public SDK via "${edge.specifier}"`);
      }
    }
    assert.deepEqual(violations, []);
  });

  test("every built-in plugin defines itself via Plugin.define / definePlugin", () => {
    const dirs = listPluginSubdirs();
    assert.ok(dirs.length >= REQUIRED_PLUGIN_GROUPS.length);
    const missingDefine: string[] = [];
    for (const dir of dirs) {
      const audit = auditDirectory(VERISTACK_ROOT, `packages/plugins/${dir}`);
      const combined = audit.files
        .map((f) => fs.readFileSync(path.join(VERISTACK_ROOT, f), "utf8"))
        .join("\n");
      if (!/\b(?:Plugin\.define|definePlugin)\s*\(/.test(combined)) {
        missingDefine.push(dir);
      }
    }
    assert.deepEqual(missingDefine, []);
  });
});

describe("Law 3 & 4: Replayable State, Open Extensible Contracts & Guarded Control Plane", () => {
  test("core implements replayable State.create with group fault isolation and batching", () => {
    const coreAudit = auditDirectory(VERISTACK_ROOT, "packages/core/src");
    const stateFiles = coreAudit.files.filter((f) => /(?:^|\/)state\.ts$/.test(f));
    assert.ok(stateFiles.length >= 1, "Expected packages/core/src/**/state.ts");
    const combined = stateFiles
      .map((f) => fs.readFileSync(path.join(VERISTACK_ROOT, f), "utf8"))
      .join("\n");
    assert.ok(combined.includes("transform"), "state.ts must support replayable transform");
    assert.ok(combined.includes("batch"), "state.ts must support notification batching");
    assert.ok(combined.includes("group"), "state.ts must support grouped fault isolation");
  });

  test("plugin SDK exposes unified replayable transforms for all 9 Veristack domains", () => {
    const sdkAudit = auditDirectory(VERISTACK_ROOT, "packages/plugin/src");
    assert.ok(sdkAudit.files.length > 0);
    const combined = sdkAudit.files
      .map((f) => fs.readFileSync(path.join(VERISTACK_ROOT, f), "utf8"))
      .join("\n");
    const missingDomains = REQUIRED_DOMAINS.filter((d) => !new RegExp(`\\b${d}\\b`).test(combined));
    assert.deepEqual(missingDomains, []);
  });

  test("core types open closed unions (Language, FindingCategory, HookHarness) and remove hardcoded CLI registries", () => {
    const coreAudit = auditDirectory(VERISTACK_ROOT, "packages/core/src");
    const sdkAudit = auditDirectory(VERISTACK_ROOT, "packages/plugin/src");
    const legacyAudit = auditDirectory(VERISTACK_ROOT, "src");
    const allFiles = [...coreAudit.files, ...sdkAudit.files, ...legacyAudit.files];
    const violations: string[] = [];
    for (const rel of allFiles) {
      const text = fs.readFileSync(path.join(VERISTACK_ROOT, rel), "utf8");
      if (/export\s+type\s+Language\s*=\s*"typescript"\s*\|/.test(text)) {
        violations.push(`${rel}: retains closed Language string literal union`);
      }
      if (/export\s+type\s+HookHarness\s*=\s*"claude"\s*\|/.test(text)) {
        violations.push(`${rel}: retains closed HookHarness union`);
      }
      if (/\bconst\s+VALID_CIRCUITS\s*=/.test(text) || /\bconst\s+VALID_PROVIDERS\s*=/.test(text)) {
        violations.push(`${rel}: retains hardcoded VALID_CIRCUITS / VALID_PROVIDERS registry`);
      }
    }
    assert.deepEqual(violations, []);
  });

  test("built-in plugin manifest enforces pre/post boot ordering and guarded anti-cheat set", () => {
    const manifestPath = Array.from(BUILTIN_MANIFEST_ALLOWLIST).find((rel) =>
      fs.existsSync(path.join(VERISTACK_ROOT, rel)),
    );
    assert.ok(manifestPath, "Expected core built-in manifest (packages/core/src/plugin/internal.ts)");
    const text = fs.readFileSync(path.join(VERISTACK_ROOT, manifestPath), "utf8");
    assert.ok(text.includes("guarded"), "Built-in manifest must declare guarded control-plane plugin IDs");
    assert.ok(/\bpre\b/.test(text), "Built-in manifest must declare pre boot phase");
    assert.ok(/\bpost\b/.test(text), "Built-in manifest must declare post boot phase");
  });
});

describe("Law 9: Core Kernel Tightness & Minimal Dependencies Budget", () => {
  test(`core kernel stays tight (<= ${MAX_CORE_KERNEL_LINES} LOC), language-agnostic, and legacy src/ <= ${MAX_LEGACY_SRC_LINES} LOC`, () => {
    const coreAudit = auditDirectory(VERISTACK_ROOT, "packages/core/src");
    const sdkAudit = auditDirectory(VERISTACK_ROOT, "packages/plugin/src");
    const legacySrcAudit = auditDirectory(VERISTACK_ROOT, "src");
    assert.ok(coreAudit.files.length > 0);
    assert.ok(sdkAudit.files.length > 0);
    assert.ok(
      coreAudit.totalLines + sdkAudit.totalLines <= MAX_CORE_KERNEL_LINES,
      `Kernel lines ${coreAudit.totalLines + sdkAudit.totalLines} exceeded ${MAX_CORE_KERNEL_LINES}`,
    );
    assert.ok(
      legacySrcAudit.totalLines <= MAX_LEGACY_SRC_LINES,
      `Legacy src/ lines ${legacySrcAudit.totalLines} exceeded ${MAX_LEGACY_SRC_LINES}`,
    );

    const leaked = coreAudit.files.filter((f) =>
      /(?:tigerstyle|wave5|wave6|wave7|t3-immune|blackhole|state-machines\/(?:rust|python|csharp))/i.test(f),
    );
    assert.deepEqual(leaked, []);

    const pkgJson = readRootPackageJson();
    const depCount = Object.keys(pkgJson.dependencies ?? {}).length;
    assert.ok(depCount <= 6, `Direct runtime dependencies (${depCount}) exceeded TigerStyle budget (<= 6)`);
  });
});
