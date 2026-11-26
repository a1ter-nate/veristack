import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import type { Finding, RepoArchetype, RungId, RungManifest, RungManifestEntry } from "../types.ts";
import { validateExecutableCommand } from "./command-audit.ts";

const VALID_ARCHETYPES = new Set<RepoArchetype>(["library", "service", "frontend", "fullstack"]);
const VALID_RUNGS = new Set<RungId>(["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]);

const HTTP_LISTENER_SIGNAL =
  /\b(?:createServer|app\.listen|fastify|new\s+Hono|Bun\.serve|Deno\.serve|new\s+Elysia|WebApplication\.CreateBuilder|http\.ListenAndServe|HttpServer::new|uvicorn\.run)\s*\(|(?<!class\s+)\b(?:FastAPI|Flask)\s*\(/;

const SAFE_ALLOW_EXCLUDED_PREFIX = /^(?:examples|fixtures|testdata|__fixtures__|snapshots)\//i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripLiteralsAndComments(content: string): string {
  return content
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, '""')
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/(^|\s)#[^\n]*/g, "$1 ")
    .replace(/\/(?:\\.|[^/\\\n])+\/[gimsuy]*/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

export function validateRungCommand(rung: RungId, command: string, repoRoot?: string): string | null {
  return validateExecutableCommand(rung, command, repoRoot);
}

function isDangerousAllowPattern(raw: string): string | null {
  const norm = raw.trim().replace(/\\/g, "/").replace(/^\/+/, "");
  if (!norm) return "empty pattern";
  if (norm.includes("..")) return "path traversal";
  if (norm.includes("**")) return "recursive ** wildcard";
  if (!SAFE_ALLOW_EXCLUDED_PREFIX.test(norm)) {
    return "allowExcluded is strictly allowlisted to examples/, fixtures/, testdata/, __fixtures__/, or snapshots/";
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
      const cmdErr = validateRungCommand(rungId, val.command.trim(), repoRoot);
      if (cmdErr) return { path: rel, error: cmdErr };
      const entry: RungManifestEntry = {
        command: val.command.trim(),
        required: typeof val.required === "boolean" ? val.required : true,
      };
      if (isRecord(val.canary) && typeof val.canary.enabled === "boolean") {
        const minKillRate = typeof val.canary.minKillRate === "number" ? Math.max(0.75, val.canary.minKillRate) : 0.8;
        const maxMutants = typeof val.canary.maxMutants === "number" ? Math.max(4, val.canary.maxMutants) : 6;
        const canaryCmd = typeof val.canary.testCommand === "string" ? val.canary.testCommand.trim() : undefined;
        if (canaryCmd) {
          const canaryErr = validateExecutableCommand("canary", canaryCmd, repoRoot);
          if (canaryErr) return { path: rel, error: canaryErr };
        }
        entry.canary = {
          enabled: val.canary.enabled,
          testCommand: canaryCmd,
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
      const reason = isDangerousAllowPattern(pat);
      if (reason) {
        return {
          path: rel,
          error: `allowExcluded pattern '${pat}' is too broad (${reason}); cannot hide source/test paths under --strict.`,
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
  if (norm === "docs/CODEOWNERS") return true;
  return !/^(?:templates|examples|samples|demo|demos|snippets|docs_src|benchmarks?|perf-measures|fuzz|docs|web\/docs|website|runtime-tests|default\/(?:agents|games|chromium))\//i.test(norm);
}

function extractManifestDependencyText(files: readonly ScannedFile[]): { prodDeps: string; uiDeps: string } {
  const prodChunks: string[] = [];
  const uiChunks: string[] = [];
  for (const f of files) {
    if (f.isTest || f.isWorkflow || f.language) continue;
    const base = path.posix.basename(f.rel).toLowerCase();
    if (base === "package.json") {
      try {
        const pkg = JSON.parse(f.content) as Record<string, unknown>;
        const selfName = typeof pkg.name === "string" ? pkg.name.toLowerCase() : "";
        const deps = isRecord(pkg.dependencies) ? Object.keys(pkg.dependencies).filter((k) => k.toLowerCase() !== selfName) : [];
        const devDeps = isRecord(pkg.devDependencies) ? Object.keys(pkg.devDependencies).filter((k) => k.toLowerCase() !== selfName) : [];
        const isPublishedLibrary = Boolean(pkg.exports) && deps.length === 0;
        prodChunks.push(deps.map((k) => `"${k}"`).join(" "));
        uiChunks.push((isPublishedLibrary ? deps : [...deps, ...devDeps]).map((k) => `"${k}"`).join(" "));
      } catch {
        prodChunks.push(f.content);
        uiChunks.push(f.content);
      }
      continue;
    }
    if (base === "pyproject.toml") {
      const nameMatch = /^\s*name\s*=\s*["']([^"']+)["']/im.exec(f.content);
      const selfPkg = nameMatch?.[1]?.toLowerCase() ?? "";
      const depLines = [...f.content.matchAll(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/gim)]
        .flatMap((m) => (m[1] ?? "").split(/\r?\n/))
        .filter((line) => !selfPkg || !line.toLowerCase().includes(selfPkg))
        .join("\n");
      prodChunks.push(depLines);
      uiChunks.push(depLines);
      continue;
    }
    if (base === "cargo.toml" || base === "go.mod" || base.endsWith(".csproj") || base === "directory.packages.props" || /^next\.config\.|^astro\.config\./.test(base)) {
      prodChunks.push(f.content);
      uiChunks.push(f.content);
    }
  }
  return { prodDeps: prodChunks.join("\n"), uiDeps: uiChunks.join("\n") };
}

export function inferArchetypeFromFiles(files: readonly ScannedFile[], relPaths: readonly string[]): RepoArchetype {
  const hostFiles = files.filter((f) => isHostRepoFile(f.rel));
  const hostPaths = relPaths.filter((p) => isHostRepoFile(p)).map((p) => p.toLowerCase());
  const { prodDeps, uiDeps } = extractManifestDependencyText(hostFiles);
  const prodSourceFiles = hostFiles.filter((f) => f.language && !f.isTest && !/(?:^|\/)(?:fixtures|testdata|__fixtures__)\//i.test(f.rel));
  const testPathSet = new Set(hostFiles.filter((f) => f.isTest).map((f) => f.rel.toLowerCase()));

  const hasReactOrUi =
    /(?:["'](?:react|next|vue|svelte|astro|@angular\/core|solid-js)["']|\b(?:react-dom|next\.config|astro\.config)\b)/i.test(uiDeps) ||
    hostPaths.some(
      (p) =>
        !testPathSet.has(p) &&
        !/(?:^|\/)(?:fixtures|testdata|__fixtures__)\//i.test(p) &&
        !/\.(?:test|spec)\.[cm]?[jt]sx$/i.test(p) &&
        (p.endsWith(".tsx") || p.endsWith(".jsx") || p.endsWith(".vue") || p.endsWith(".svelte") || p.endsWith(".astro")),
    );
  const hasBackendService =
    /\b(?:express|fastify|hono|@hono\/node-server|elysia|nestjs|koa|fastapi|django|flask|actix-web|axum|gin-gonic|labstack\/echo|go-chi\/chi|gofiber\/fiber|google\.golang\.org\/grpc|microsoft\.aspnetcore|microsoft\.net\.sdk\.web)\b/i.test(
      prodDeps,
    ) ||
    prodSourceFiles.some((f) => HTTP_LISTENER_SIGNAL.test(stripLiteralsAndComments(f.content)) || /\b(?:http\.Serve|e\.Start)\s*\(/.test(stripLiteralsAndComments(f.content))) ||
    hostPaths.some((p) => p.includes("dockerfile") || p.includes("controllers/") || p.includes("routes/"));

  if (hasReactOrUi && hasBackendService) return "fullstack";
  if (hasReactOrUi) return "frontend";
  if (hasBackendService) return "service";
  return "library";
}

export function auditDeclaredArchetype(
  manifest: RungManifest | undefined,
  observedArchetype: RepoArchetype,
  repo?: DiscoveredRepo,
): Finding[] {
  if (!manifest) return [];
  const findings: Finding[] = [];
  const isDowngrade = (declared: RepoArchetype, observed: RepoArchetype): boolean =>
    (declared === "library" && observed !== "library") ||
    (declared === "frontend" && (observed === "service" || observed === "fullstack")) ||
    (declared === "service" && (observed === "frontend" || observed === "fullstack"));

  if (isDowngrade(manifest.archetype, observedArchetype)) {
    findings.push({
      id: "RUNG:archetype-mismatch:.verification/rungs.json",
      rule: "rung-archetype-mismatch",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: `Declared archetype '${manifest.archetype}' contradicts observed repo signals ('${observedArchetype}'), which would excuse required rungs.`,
      fix: `Set archetype in .verification/rungs.json to '${observedArchetype}' so all applicable rungs are enforced.`,
    });
  }
  if (repo && manifest.workspaces) {
    for (const ws of manifest.workspaces) {
      const prefix = `${ws.path}/`;
      const childPrefixes = manifest.workspaces
        .filter((other) => other.path !== ws.path && other.path.startsWith(prefix))
        .map((other) => `${other.path}/`);
      const inWs = (p: string): boolean => p.startsWith(prefix) && !childPrefixes.some((cp) => p.startsWith(cp));
      const subFiles = repo.files.filter((f) => inWs(f.rel));
      const subPaths = repo.allRelPaths.filter((p) => inWs(p));
      const obs = inferArchetypeFromFiles(subFiles, subPaths);
      if (isDowngrade(ws.archetype, obs)) {
        findings.push({
          id: `RUNG:workspace-archetype-mismatch:${ws.path}`,
          rule: "rung-archetype-mismatch",
          category: "oracle-lock",
          rung: "R0",
          severity: "error",
          file: ".verification/rungs.json",
          line: 1,
          message: `Workspace '${ws.name}' declares archetype '${ws.archetype}' but exhibits '${obs}' signals.`,
          fix: `Update workspace '${ws.name}' archetype to '${obs}' in .verification/rungs.json.`,
        });
      }
    }
  }
  return findings;
}

export function discoverWorkspaces(
  repo: DiscoveredRepo,
  manifest?: RungManifest,
): Array<{ name: string; path: string; archetype: RepoArchetype }> {
  const discovered: Array<{ name: string; path: string; archetype: RepoArchetype }> = [];
  const seen = new Set<string>();
  if (manifest?.workspaces) {
    for (const ws of manifest.workspaces) {
      seen.add(ws.path);
      discovered.push(ws);
    }
  }

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
    if (/(?:^|\/)(?:node_modules|fixtures|testdata|__fixtures__|test|tests|lint|benchmarks?|bench|fuzz|scripts|perf-measures|docs_src|docs|samples|demo|demos|snippets|e2e|stories|website|site|proc-macros?|gen-protos?|npm)(?:\/|$)|^tools\/(?:oxlint|eslint|lint)(?:\/|$)|^common\/[^/]*config(?:\/|$)|(?:^|\/)(?:eslint|vitest|tsconfig|prettier|biome)-config(?:\/|$)|^web\/docs(?:\/|$)/i.test(dir)) continue;
    if (/(?:^|\/)[^/]+\.(?:tests?|unittests|integrationtests|specs?)$/i.test(dir)) continue;
    if (base === "Cargo.toml" && /^\s*\[workspace\]/m.test(file.content) && !/^\s*\[package\]/m.test(file.content)) continue;
    if (base.endsWith(".csproj") && (/<IsTestProject>\s*true\s*<\/IsTestProject>/i.test(file.content) || /Microsoft\.NET\.Test\.Sdk|PackageReference\s+Include="(?:xunit|NUnit|MSTest\.TestFramework)"/i.test(file.content))) continue;
    seen.add(dir);
    discovered.push({ name: dir, path: dir, archetype: "library" });
  }
  const filtered: Array<{ name: string; path: string; archetype: RepoArchetype }> = [];
  for (const ws of discovered) {
    const isExplicit = Boolean(manifest?.workspaces?.some((m) => m.path === ws.path));
    const prefix = `${ws.path}/`;
    const childPrefixes = discovered
      .filter((other) => other.path !== ws.path && other.path.startsWith(prefix))
      .map((other) => `${other.path}/`);
    const inWs = (p: string): boolean => p.startsWith(prefix) && !childPrefixes.some((cp) => p.startsWith(cp));
    const subFiles = repo.files.filter((f) => inWs(f.rel));
    const subPaths = repo.allRelPaths.filter((p) => inWs(p));
    const subProd = subFiles.filter((f) => f.language && !f.isTest && !/(?:^|\/)examples\//i.test(f.rel));
    const hasProd = subProd.length > 0;
    const isRustReexportOnly =
      hasProd &&
      subProd.every(
        (f) => f.language === "rust" && !/\b(?:fn|struct|enum|impl|trait|macro_rules!)\b/.test(stripLiteralsAndComments(f.content)),
      );
    if (!isExplicit && (!hasProd || isRustReexportOnly)) continue;
    const arch = isExplicit ? ws.archetype : inferArchetypeFromFiles(subFiles, subPaths);
    filtered.push({ name: ws.name, path: ws.path, archetype: arch });
  }
  return filtered.sort((a, b) => a.path.localeCompare(b.path));
}
