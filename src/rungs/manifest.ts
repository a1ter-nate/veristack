import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import type { Finding, RepoArchetype, RungId, RungManifest, RungManifestEntry } from "../types.ts";

const VALID_ARCHETYPES = new Set<RepoArchetype>(["library", "service", "frontend", "fullstack"]);
const VALID_RUNGS = new Set<RungId>(["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]);

const HTTP_LISTENER_SIGNAL =
  /\b(?:createServer|app\.listen|fastify|new\s+Hono|WebApplication\.CreateBuilder|http\.ListenAndServe|HttpServer::new|uvicorn\.run|FastAPI|Flask)\s*\(/;

function stripLiteralsAndComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/\/(?:\\.|[^/\\\n])+\/[gimsuy]*/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
      const entry: RungManifestEntry = {
        command: val.command.trim(),
        required: typeof val.required === "boolean" ? val.required : true,
      };
      if (isRecord(val.canary) && typeof val.canary.enabled === "boolean") {
        entry.canary = {
          enabled: val.canary.enabled,
          testCommand: typeof val.canary.testCommand === "string" ? val.canary.testCommand.trim() : undefined,
          targets: Array.isArray(val.canary.targets)
            ? val.canary.targets.filter((t): t is string => typeof t === "string" && t.trim().length > 0)
            : undefined,
          maxMutants: typeof val.canary.maxMutants === "number" ? val.canary.maxMutants : undefined,
          minKillRate: typeof val.canary.minKillRate === "number" ? val.canary.minKillRate : undefined,
        };
      }
      rungs[key as RungId] = entry;
    }
    const allowExcluded = Array.isArray(parsed.allowExcluded)
      ? parsed.allowExcluded.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
      : [];
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
  const prodSourceFiles = hostFiles.filter((f) => f.language && !f.isTest && f.rel !== "src/rungs/manifest.ts");

  const hasReactOrUi =
    /(?:["'](?:react|next|vue|svelte|@angular\/core|solid-js)["']|\b(?:react-dom|next\.config)\b)/i.test(manifestText) ||
    hostPaths.some((p) => p.endsWith(".tsx") || p.endsWith(".jsx") || p.endsWith(".vue") || p.endsWith(".svelte"));
  const hasBackendService =
    /\b(?:express|fastify|hono|nestjs|koa|fastapi|django|flask|actix-web|axum|gin-gonic|microsoft\.aspnetcore)\b/i.test(
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
    if (base !== "package.json" && base !== "Cargo.toml" && !base.endsWith(".csproj")) continue;
    const dir = path.posix.dirname(norm);
    if (dir === "." || dir === "" || seen.has(dir)) continue;
    if (!/^(?:apps|packages|services|crates|libs)\/[^/]+$/.test(dir)) continue;
    seen.add(dir);
    const subFiles = repo.files.filter((f) => f.rel.startsWith(`${dir}/`));
    const subPaths = repo.allRelPaths.filter((p) => p.startsWith(`${dir}/`));
    const arch = inferArchetypeFromFiles(subFiles, subPaths);
    discovered.push({ name: dir, path: dir, archetype: arch });
  }
  return discovered.sort((a, b) => a.path.localeCompare(b.path));
}
