import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import type { Finding, RepoArchetype, RungId, RungManifest, RungManifestEntry } from "../types.ts";
import { sanitizeShellBlock } from "./workflow-audit.ts";

const VALID_ARCHETYPES = new Set<RepoArchetype>(["library", "service", "frontend", "fullstack"]);
const VALID_RUNGS = new Set<RungId>(["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]);

const HTTP_LISTENER_SIGNAL =
  /\b(?:createServer|app\.listen|fastify|new\s+Hono|Bun\.serve|Deno\.serve|new\s+Elysia|WebApplication\.CreateBuilder|http\.ListenAndServe|HttpServer::new|uvicorn\.run|FastAPI|Flask)\s*\(/;

const RUNG_TOOL_REQUIREMENTS: Partial<Record<RungId, RegExp>> = {
  R0: /\b(?:oxlint|oxfmt|eslint|prettier|biome|ruff|clippy|cargo\s+fmt|dotnet\s+format|gofmt|golangci-lint|vstack|cli\.ts|lint:)\b/i,
  R1: /\b(?:tsc|tsgo|mypy|pyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+vet|knip|deslop-please|check-max-lines|typecheck)\b/i,
  R2: /\b(?:bun\s+test|vitest|jest|node\s+--test|mocha|ava|dotnet\s+test|cargo\s+(?:test|nextest)|pytest|go\s+test|phpunit|rspec|npm\s+test|pnpm\s+test)\b/i,
  R3: /\b(?:bun\s+test|vitest|jest|node\s+--test|dotnet\s+test|cargo\s+(?:test|nextest)|pytest|go\s+test|pact|storybook|test:mbt|test:contract|test:component)\b/i,
  R4: /\b(?:bun\s+test|vitest|jest|dotnet\s+test|cargo\s+(?:test|nextest)|pytest|go\s+test|testcontainers|migrate|emulator|test:int)\b/i,
  R5: /\b(?:stryker|mutmut|cargo\s+mutants|pitest|canary|formal-sync|laws|bend|quint|dafny|kani|stateright|chromatic|percy|argos|bombadil)\b/i,
  R6: /\b(?:k6|BenchmarkDotNet|cargo\s+bench|pytest-benchmark|pytest\s+--benchmark|go\s+test[^\n]*-bench|lighthouse|lhci|perf:check|check-perf-budget|big-o|spc)\b/i,
  R7: /\b(?:playwright|cypress|maestro|test:e2e|e2e)\b/i,
  R8: /\b(?:synthetic|canary|rollback|smoke-prod|post-deploy|healthcheck)\b/i,
};

const DANGEROUS_ALLOW_EXCLUDED = /^(?:\*{1,2}|src\/?(?:\*{1,2})?|lib\/?(?:\*{1,2})?|app\/?(?:\*{1,2})?|apps\/?(?:\*{1,2})?|packages\/?(?:\*{1,2})?|tests\/?(?:\*{1,2})?|\.\*)$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripLiteralsAndComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/\/(?:\\.|[^/\\\n])+\/[gimsuy]*/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

export function validateRungCommand(rung: RungId, command: string): string | null {
  const activeLines = sanitizeShellBlock(command);
  if (activeLines.length === 0) {
    return `Rung ${rung} command '${command}' is a no-op or swallows failures.`;
  }
  const active = activeLines.join(" ");
  if (/\|\|\s*(?:true|echo|printf|:|exit\s+0)\b|\bset\s+\+e\b|\bexit\s+0\b|\bgit\s+(?:diff|status)\b/.test(active)) {
    return `Rung ${rung} command contains forbidden failure-swallowing or diff-cheating syntax.`;
  }
  const requiredTool = RUNG_TOOL_REQUIREMENTS[rung];
  if (requiredTool && !requiredTool.test(active)) {
    return `Rung ${rung} command '${command}' does not invoke a recognized ${rung} verification tool.`;
  }
  return null;
}

export function loadRungManifest(repoRoot: string): { path?: string; manifest?: RungManifest; error?: string } {
  const rel = ".verification/rungs.json";
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) return {};
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(abs, "utf8"));
    if (!isRecord(parsed)) return { path: rel, error: `${rel} must be a JSON object.` };
    const arch = parsed.archetype;
    if (typeof arch !== "string" || !VALID_ARCHETYPES.has(arch as RepoArchetype)) {
      return { path: rel, error: `${rel} must declare valid archetype (library|service|frontend|fullstack).` };
    }
    const rawRungs = isRecord(parsed.rungs) ? parsed.rungs : {};
    const rungs: Partial<Record<RungId, RungManifestEntry>> = {};
    for (const [key, val] of Object.entries(rawRungs)) {
      if (!VALID_RUNGS.has(key as RungId) || !isRecord(val)) continue;
      if (typeof val.command !== "string" || val.command.trim().length === 0) continue;
      const rungId = key as RungId;
      const cmdErr = validateRungCommand(rungId, val.command.trim());
      if (cmdErr) return { path: rel, error: cmdErr };
      const entry: RungManifestEntry = {
        command: val.command.trim(),
        required: typeof val.required === "boolean" ? val.required : true,
      };
      if (isRecord(val.canary) && typeof val.canary.enabled === "boolean") {
        const minKillRate = typeof val.canary.minKillRate === "number" ? Math.max(0.75, val.canary.minKillRate) : 0.8;
        const maxMutants = typeof val.canary.maxMutants === "number" ? Math.max(4, val.canary.maxMutants) : 6;
        entry.canary = {
          enabled: val.canary.enabled,
          testCommand: typeof val.canary.testCommand === "string" ? val.canary.testCommand.trim() : undefined,
          targets: Array.isArray(val.canary.targets)
            ? val.canary.targets.filter((t): t is string => typeof t === "string" && t.trim().length > 0)
            : undefined,
          maxMutants,
          minKillRate,
        };
      }
      rungs[rungId] = entry;
    }

    const allowExcluded = Array.isArray(parsed.allowExcluded)
      ? parsed.allowExcluded.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
      : [];
    for (const pat of allowExcluded) {
      if (DANGEROUS_ALLOW_EXCLUDED.test(pat.trim().replace(/^\/+/, ""))) {
        return {
          path: rel,
          error: `allowExcluded pattern '${pat}' is too broad; cannot exclude source/test roots under --strict.`,
        };
      }
      if (pat.trim().replace(/^\/+/, "").startsWith("src/")) {
        return {
          path: rel,
          error: `allowExcluded pattern '${pat}' excludes production source under src/, which is forbidden.`,
        };
      }
    }

    const workspaces = Array.isArray(parsed.workspaces)
      ? parsed.workspaces
          .filter(
            (w): w is { name: string; path: string; archetype: RepoArchetype } =>
              isRecord(w) &&
              typeof w.name === "string" &&
              typeof w.path === "string" &&
              typeof w.archetype === "string" &&
              VALID_ARCHETYPES.has(w.archetype as RepoArchetype),
          )
          .map((w) => ({ name: w.name, path: w.path.replace(/^\/+|\/+$/g, ""), archetype: w.archetype }))
      : undefined;

    return {
      path: rel,
      manifest: {
        schemaVersion: 1,
        archetype: arch as RepoArchetype,
        allowExcluded,
        rungs,
        workspaces,
      },
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { path: rel, error: `Invalid JSON in ${rel}: ${msg}` };
  }
}

export function isHostRepoFile(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return !/^(?:templates|examples)\//.test(norm);
}

export function inferArchetypeFromFiles(files: readonly ScannedFile[], relPaths: readonly string[]): RepoArchetype {
  const hostFiles = files.filter((f) => isHostRepoFile(f.rel));
  const hostPaths = relPaths.filter((p) => isHostRepoFile(p)).map((p) => p.toLowerCase());
  const manifestText = hostFiles
    .filter((f) => !f.isTest && !f.isWorkflow && !f.language && !f.rel.toLowerCase().endsWith(".md"))
    .map((f) => f.content)
    .join("\n");
  const prodSourceFiles = hostFiles.filter((f) => f.language && !f.isTest);

  const hasReactOrUi =
    /(?:["'](?:react|next|vue|svelte|@angular\/core|solid-js)["']|\b(?:react-dom|next\.config)\b)/i.test(manifestText) ||
    hostPaths.some((p) => p.endsWith(".tsx") || p.endsWith(".jsx") || p.endsWith(".vue") || p.endsWith(".svelte"));
  const hasBackendService =
    /\b(?:express|fastify|hono|@hono\/node-server|elysia|nestjs|koa|fastapi|django|flask|actix-web|axum|gin-gonic|microsoft\.aspnetcore|microsoft\.net\.sdk\.web)\b/i.test(
      manifestText,
    ) ||
    prodSourceFiles.some((f) => HTTP_LISTENER_SIGNAL.test(stripLiteralsAndComments(f.content))) ||
    hostPaths.some((p) => p.includes("dockerfile") || p.includes("controllers/") || p.includes("routes/"));

  if (hasReactOrUi && hasBackendService) return "fullstack";
  if (hasReactOrUi) return "frontend";
  if (hasBackendService) return "service";
  return "library";
}

export function auditDeclaredArchetype(
  manifest: RungManifest | undefined,
  observedArchetype: RepoArchetype,
): Finding[] {
  if (!manifest) return [];
  const declared = manifest.archetype;
  const downgrade =
    (declared === "library" && observedArchetype !== "library") ||
    (declared === "frontend" && (observedArchetype === "service" || observedArchetype === "fullstack")) ||
    (declared === "service" && (observedArchetype === "frontend" || observedArchetype === "fullstack"));
  if (!downgrade) return [];
  return [
    {
      id: "RUNG:archetype-mismatch:.verification/rungs.json",
      rule: "rung-archetype-mismatch",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: `Declared archetype '${declared}' contradicts observed repo signals ('${observedArchetype}'), which would excuse required rungs.`,
      fix: `Set archetype in .verification/rungs.json to '${observedArchetype}' so all applicable rungs are enforced.`,
    },
  ];
}

export function discoverWorkspaces(
  repo: DiscoveredRepo,
  manifest?: RungManifest,
): Array<{ name: string; path: string; archetype: RepoArchetype }> {
  if (manifest?.workspaces && manifest.workspaces.length > 0) return manifest.workspaces;

  const discovered: Array<{ name: string; path: string; archetype: RepoArchetype }> = [];
  const seen = new Set<string>();

  for (const file of repo.files) {
    const norm = file.rel.replace(/\\/g, "/");
    if (!isHostRepoFile(norm)) continue;
    const base = path.posix.basename(norm);
    if (
      base !== "package.json" &&
      base !== "Cargo.toml" &&
      base !== "pyproject.toml" &&
      base !== "go.mod" &&
      !base.endsWith(".csproj")
    ) {
      continue;
    }
    const dir = path.posix.dirname(norm);
    if (dir === "." || dir === "" || seen.has(dir)) continue;
    if (!/^(?:apps|packages|services|crates|libs|src|cmd)\/[^/]+$/.test(dir)) continue;
    seen.add(dir);
    const subFiles = repo.files.filter((f) => f.rel.startsWith(`${dir}/`));
    const subPaths = repo.allRelPaths.filter((p) => p.startsWith(`${dir}/`));
    const arch = inferArchetypeFromFiles(subFiles, subPaths);
    discovered.push({ name: dir, path: dir, archetype: arch });
  }
  return discovered.sort((a, b) => a.path.localeCompare(b.path));
}
