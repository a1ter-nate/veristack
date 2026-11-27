import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";
import {
  extractFunctionUnits,
  hasSafetyDirective,
  lineAtOffset,
  maskTigerCode,
  pushTigerFinding,
  resolveTigerLang,
  type TigerLang,
} from "./helpers.ts";

const MAX_PARAMS = 4;
const MAX_INTERFACE_METHODS = 8;
const LIB_RUNTIME_DEP_MAX = 20;
const SVC_RUNTIME_DEP_MAX = 40;

function checkFunctionSignatures(file: ScannedFile, lines: readonly string[], findings: Finding[]): void {
  const units = extractFunctionUnits(file);
  for (const unit of units) {
    if (hasSafetyDirective(lines, unit.startLine)) continue;
    if (unit.paramCount > MAX_PARAMS) {
      pushTigerFinding(findings, {
        rule: "tiger-interface-surface",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line: unit.startLine,
        message: `Function '${unit.name}' accepts ${unit.paramCount} positional parameters (TigerStyle cap: ${MAX_PARAMS}).`,
        fix: "Group related parameters into a typed options/request object or domain struct.",
      });
    }
    if (unit.boolParamCount >= 2) {
      pushTigerFinding(findings, {
        rule: "tiger-interface-surface",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line: unit.startLine,
        message: `Function '${unit.name}' takes ${unit.boolParamCount} boolean flags (boolean flag soup).`,
        fix: "Replace multiple boolean parameters with an explicit discriminated union or mode enum.",
      });
    }
  }
}

function checkInterfaceAndTableSurface(file: ScannedFile, lang: TigerLang, lines: readonly string[], findings: Finding[]): void {
  if (!file.content) return;
  const masked = maskTigerCode(file.content, lang);
  if (lang === "sql") {
    for (const m of masked.matchAll(/\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_."]+)\s*\(([\s\S]*?)\)\s*;/gi)) {
      const body = m[2] ?? "";
      const nullableStateCols = body.match(/\b(?:approved|rejected|cancelled|canceled|completed|failed|shipped|archived)_at\b(?![^,\n]*\bNOT\s+NULL\b)/gi) ?? [];
      if (nullableStateCols.length >= 3 && !/\bCHECK\s*\(/i.test(body)) {
        const ln = lineAtOffset(file.content, m.index ?? 0);
        if (!hasSafetyDirective(lines, ln)) {
          pushTigerFinding(findings, {
            rule: "tiger-interface-surface",
            rung: "R1",
            severity: "warn",
            file: file.rel,
            line: ln,
            message: `SQL table '${m[1]}' has ${nullableStateCols.length} nullable lifecycle columns without a mutual-exclusion CHECK.`,
            fix: "Add a CHECK constraint enforcing mutually exclusive states or normalize into an explicit status enum.",
          });
        }
      }
    }
    return;
  }
  const ifaceRe =
    lang === "rust"
      ? /\b(?:pub\s+)?trait\s+([A-Za-z_]\w*)[^{]*\{([^}]*)\}/g
      : lang === "go"
        ? /\btype\s+([A-Za-z_]\w*)\s+interface\s*\{([^}]*)\}/g
        : lang === "csharp"
          ? /\b(?:public|internal)\s+interface\s+([A-Za-z_]\w*)[^{]*\{([^}]*)\}/g
          : /\b(?:export\s+)?interface\s+([A-Za-z_]\w*)[^{]*\{([^}]*)\}/g;
  for (const m of masked.matchAll(ifaceRe)) {
    const body = m[2] ?? "";
    const methodCount = (body.match(/\([^)]*\)\s*(?::|=>|;|\n)/g) ?? []).length;
    if (methodCount > MAX_INTERFACE_METHODS) {
      const ln = lineAtOffset(file.content, m.index ?? 0);
      if (!hasSafetyDirective(lines, ln)) {
        pushTigerFinding(findings, {
          rule: "tiger-interface-surface",
          rung: "R1",
          severity: "warn",
          file: file.rel,
          line: ln,
          message: `Interface/trait '${m[1]}' declares ${methodCount} methods (cap: ${MAX_INTERFACE_METHODS}).`,
          fix: "Split wide interfaces into small, cohesive capability interfaces.",
        });
      }
    }
  }
}

export function countDirectRuntimeDependencies(repo: DiscoveredRepo): { count: number; manifestFile?: string } {
  if (!repo.files.length) return { count: 0 };
  const rootPkg = repo.files.find((f) => f.rel === "package.json");
  if (rootPkg) {
    try {
      const parsed = JSON.parse(rootPkg.content) as { dependencies?: Record<string, unknown> };
      const deps = parsed.dependencies && typeof parsed.dependencies === "object" ? Object.keys(parsed.dependencies) : [];
      return { count: deps.length, manifestFile: "package.json" };
    } catch { return { count: 0, manifestFile: "package.json" }; }
  }
  const cargo = repo.files.find((f) => f.rel === "Cargo.toml");
  if (cargo) {
    const sec = /\[dependencies\]([\s\S]*?)(?:\n\[|$)/.exec(cargo.content)?.[1] ?? "";
    const count = sec.split(/\r?\n/).filter((l) => /^\s*[A-Za-z0-9_-]+\s*=/.test(l)).length;
    return { count, manifestFile: "Cargo.toml" };
  }
  const goMod = repo.files.find((f) => f.rel === "go.mod");
  if (goMod) {
    const count = goMod.content.split(/\r?\n/).filter((l) => /^\s*[a-z0-9.-]+\/\S+\s+v\d/.test(l) && !/\/\/\s*indirect/.test(l)).length;
    return { count, manifestFile: "go.mod" };
  }
  const py = repo.files.find((f) => f.rel === "pyproject.toml");
  if (py) {
    const m = /^\s*dependencies\s*=\s*\[([\s\S]*?)\]/im.exec(py.content);
    const count = m?.[1] ? m[1].split(/\r?\n/).filter((l) => /["'][A-Za-z0-9_.-]+/.test(l)).length : 0;
    return { count, manifestFile: "pyproject.toml" };
  }
  const csprojs = repo.files.filter((f) => f.rel.endsWith(".csproj") && !/tests?/i.test(path.posix.basename(f.rel)));
  if (csprojs.length > 0) {
    const refs = new Set<string>();
    for (const c of csprojs) for (const m of c.content.matchAll(/<PackageReference\s+Include="([^"]+)"/gi)) if (m[1]) refs.add(m[1]);
    return { count: refs.size, manifestFile: csprojs[0]?.rel };
  }
  return { count: 0 };
}

export function analyzeTigerInterfacesAndDeps(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    const lang = resolveTigerLang(file);
    if (!lang) continue;
    const lines = file.content.split(/\r?\n/);
    checkFunctionSignatures(file, lines, findings);
    checkInterfaceAndTableSurface(file, lang, lines, findings);
  }
  const depInfo = countDirectRuntimeDependencies(repo);
  const depLimit = repo.archetype === "library" ? LIB_RUNTIME_DEP_MAX : SVC_RUNTIME_DEP_MAX;
  if (depInfo.manifestFile && depInfo.count > depLimit) {
    pushTigerFinding(findings, {
      rule: "tiger-minimal-dependencies",
      rung: "R0",
      severity: "warn",
      file: depInfo.manifestFile,
      line: 1,
      message: `${depInfo.manifestFile} declares ${depInfo.count} direct runtime dependencies (cap for ${repo.archetype}: ${depLimit}).`,
      fix: "Minimize direct runtime dependencies and audit/prune non-essential packages.",
    });
  }
  return findings;
}
