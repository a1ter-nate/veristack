import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import { type AstNode, getMemberChain, isAstNode, parseTsAst, walkAst } from "./ts-ast.ts";

const DANGEROUS_SINKS = new Set([
  "eval",
  "Function",
  "exec",
  "execSync",
  "child_process.exec",
  "child_process.execSync",
  "res.redirect",
  "res.sendFile",
]);

const SSR_ROUTE_PATH = /(?:^|\/)(?:app|pages|routes|server)\/[^/]*\.(?:[cm]?[jt]sx?)$/i;
const SSR_HANDLER_EXPORT = /\bexport\s+(?:async\s+)?function\s+(?:loader|action|GET|POST|PUT|DELETE|getServerSideProps)\b/;
const MODULE_MUTABLE_DECL = /^(?:let\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=|const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+(?:Map|Set)(?:<[^>\n]+>)?\s*\(|\[\s*\]|\{\s*\}))/gm;

const ASPNET_MW_ORDER = [
  "UseExceptionHandler",
  "UseRouting",
  "UseCors",
  "UseAuthentication",
  "UseAuthorization",
  "UseAntiforgery",
  "MapControllers",
] as const;

const CS_SINGLETON_REG = /\.AddSingleton\s*<\s*(?:[A-Za-z0-9_.]+\s*,\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*>/g;
const CS_SCOPED_REG = /\.AddScoped\s*<\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?\s*>/g;

const CELERY_ACKS_LATE = /\backs_late\s*=\s*True\b/g;
const K8S_LISTER_GET = /([A-Za-z_][A-Za-z0-9_]*)\s*,[^=\n]*:=\s*[^;\n]*(?:Lister\s*\(\s*\)|informer)[^;\n]*\.Get\s*\(/g;
const AGENT_PENDING_MAP = /\b(pending[A-Za-z0-9_]*|inFlight[A-Za-z0-9_]*|rpcCalls)\s*\.\s*set\s*\(/g;
const SECRET_SCRUB_LOOP = /\bfor\s*\(\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s+of\s+([A-Za-z_][A-Za-z0-9_.]*secrets?[A-Za-z0-9_.]*)\s*\)\s*\{[^}]{0,220}\.replace(?:All)?\s*\(\s*\1\b/gi;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `BH:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function resolveImport(fromRel: string, spec: string, allFiles: Set<string>): string | null {
  if (!spec.startsWith(".")) return null;
  const dir = path.posix.dirname(fromRel);
  const base = path.posix.normalize(path.posix.join(dir, spec));
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.mts`,
    base.replace(/\.js$/, ".ts"),
    `${base}/index.ts`,
    `${base}/index.js`,
  ];
  for (const c of candidates) {
    if (allFiles.has(c)) return c;
  }
  return null;
}

function analyzeTsCrossFileGraph(repo: DiscoveredRepo, findings: Finding[]): void {
  const tsFiles = repo.files.filter(
    (f) => (f.language === "typescript" || f.language === "javascript") && !f.isTest && !f.rel.includes("examples/"),
  );
  if (tsFiles.length < 2) return;

  const allPaths = new Set(tsFiles.map((f) => f.rel));
  const adj = new Map<string, Array<{ target: string; line: number }>>();
  const exportedSinkWrappers = new Map<string, Set<string>>();
  const exportedCacheModules = new Map<string, { invalidators: Set<string> }>();
  const parsedMap = new Map<string, AstNode>();

  for (const file of tsFiles) {
    const ast = parseTsAst(file);
    if (!ast) continue;
    parsedMap.set(file.rel, ast);

    const edges: Array<{ target: string; line: number }> = [];
    const sinks = new Set<string>();
    const invalidators = new Set<string>();
    let definesCache = false;

    const body = Array.isArray(ast.body) ? ast.body : [];
    for (const stmt of body) {
      if (!isAstNode(stmt)) continue;

      if (stmt.type === "ImportDeclaration" && stmt.importKind !== "type" && isAstNode(stmt.source) && typeof stmt.source.value === "string") {
        const specs = Array.isArray(stmt.specifiers) ? stmt.specifiers : [];
        const allTypeSpecs = specs.length > 0 && specs.every((s) => isAstNode(s) && s.importKind === "type");
        if (!allTypeSpecs) {
          const resolved = resolveImport(file.rel, stmt.source.value, allPaths);
          if (resolved && resolved !== file.rel) {
            edges.push({ target: resolved, line: lineOf(file.content, stmt.start ?? 0) });
          }
        }
      }

      if (stmt.type === "VariableDeclaration" && Array.isArray(stmt.declarations)) {
        for (const d of stmt.declarations) {
          if (isAstNode(d) && isAstNode(d.init) && d.init.type === "NewExpression" && isAstNode(d.init.callee)) {
            const cn = getMemberChain(d.init.callee);
            if (cn === "Map" || cn === "LRUCache") definesCache = true;
          }
        }
      }

      if (stmt.type === "ExportNamedDeclaration" && isAstNode(stmt.declaration)) {
        const decl = stmt.declaration;
        if (decl.type === "FunctionDeclaration" && isAstNode(decl.id) && typeof decl.id.name === "string") {
          const fnName = decl.id.name;
          if (/^(?:invalidate|evict|clear|delete|purge|bust)/i.test(fnName)) invalidators.add(fnName);
          let callsDangerousSink = false;
          walkAst(decl, (cur) => {
            if (callsDangerousSink) return;
            if ((cur.type === "CallExpression" || cur.type === "NewExpression") && isAstNode(cur.callee)) {
              const cn = getMemberChain(cur.callee);
              if (DANGEROUS_SINKS.has(cn)) callsDangerousSink = true;
            }
          });
          if (callsDangerousSink) sinks.add(fnName);
        }
      }
    }

    adj.set(file.rel, edges);
    if (sinks.size > 0) exportedSinkWrappers.set(file.rel, sinks);
    if (definesCache && invalidators.size > 0) exportedCacheModules.set(file.rel, { invalidators });
  }

  const visited = new Set<string>();
  const inStack = new Set<string>();
  const reportedCycles = new Set<string>();

  const dfs = (node: string, trail: string[]): void => {
    visited.add(node);
    inStack.add(node);
    try {
      for (const edge of adj.get(node) ?? []) {
        if (inStack.has(edge.target)) {
          const cycleStart = trail.indexOf(edge.target);
          const cycleNodes = cycleStart >= 0 ? [...trail.slice(cycleStart), edge.target] : [node, edge.target];
          const key = [...cycleNodes].sort().join("|");
          if (!reportedCycles.has(key)) {
            reportedCycles.add(key);
            push(
              findings, node, edge.line, "graph-circular-module-dependency", "R1", "warn",
              `Runtime circular import cycle detected: ${cycleNodes.join(" -> ")}.`,
              "Break the runtime cycle by extracting shared types/helpers into a lower-layer module or using 'import type'.",
            );
          }
        } else if (!visited.has(edge.target)) {
          dfs(edge.target, [...trail, edge.target]);
        }
      }
    } finally {
      inStack.delete(node);
    }
  };
  for (const node of adj.keys()) {
    if (!visited.has(node)) dfs(node, [node]);
  }

  for (const file of tsFiles) {
    const ast = parsedMap.get(file.rel);
    if (!ast) continue;
    const importedWrappers = new Map<string, string>();
    const importedCacheInvalidators = new Set<string>();
    let importsCacheModule = false;

    const body = Array.isArray(ast.body) ? ast.body : [];
    for (const stmt of body) {
      if (!isAstNode(stmt) || stmt.type !== "ImportDeclaration" || stmt.importKind === "type") continue;
      if (!isAstNode(stmt.source) || typeof stmt.source.value !== "string") continue;
      const target = resolveImport(file.rel, stmt.source.value, allPaths);
      if (!target) continue;
      const sinks = exportedSinkWrappers.get(target);
      const cacheInfo = exportedCacheModules.get(target);
      if (cacheInfo) importsCacheModule = true;
      const specs = Array.isArray(stmt.specifiers) ? stmt.specifiers : [];
      for (const sp of specs) {
        if (!isAstNode(sp) || sp.type !== "ImportSpecifier") continue;
        const orig = isAstNode(sp.imported) && typeof sp.imported.name === "string" ? sp.imported.name : "";
        const local = isAstNode(sp.local) && typeof sp.local.name === "string" ? sp.local.name : orig;
        if (sinks?.has(orig)) importedWrappers.set(local, `${target}:${orig}`);
        if (cacheInfo?.invalidators.has(orig)) importedCacheInvalidators.add(local);
      }
    }

    if (importedWrappers.size > 0) {
      walkAst(ast, (node) => {
        if (node.type === "CallExpression" && isAstNode(node.callee) && node.callee.type === "Identifier" && typeof node.callee.name === "string") {
          const wrapped = importedWrappers.get(node.callee.name);
          if (!wrapped || !Array.isArray(node.arguments)) return;
          const argText = file.content.slice(node.start ?? 0, node.end ?? 0);
          if (/\b(?:req|request)\.(?:body|query|params|headers)\b/.test(argText)) {
            push(
              findings, file.rel, lineOf(file.content, node.start ?? 0), "graph-wrapper-escaped-sink", "R0", "error",
              `Tainted request input flows into cross-file dangerous sink wrapper '${node.callee.name}' (${wrapped}).`,
              "Validate/parameterize untrusted input before passing it across module boundaries into shell/eval/redirect wrappers.",
            );
          }
        }
      });
    }

    if (importsCacheModule && importedCacheInvalidators.size === 0) {
      const code = maskCode(file.content, file.language);
      const writeMatch = /\.(?:insert|update|delete|upsert|save|setDoc|updateDoc|deleteDoc)\s*\(/.exec(code);
      if (writeMatch && writeMatch.index !== undefined) {
        push(
          findings, file.rel, lineOf(file.content, writeMatch.index), "graph-cross-file-dao-cache-drift", "R1", "warn",
          "Module imports a cached repository/store and performs DB writes without importing or invoking its cache invalidator.",
          "Import and call the cache module's invalidate/evict helper after mutating persistent state.",
        );
      }
    }
  }
}

function analyzeDotnetArchGates(repo: DiscoveredRepo, findings: Finding[]): void {
  const csFiles = repo.files.filter((f) => f.language === "csharp" && !f.isTest);
  if (csFiles.length === 0) return;

  const singletons = new Map<string, { file: string; line: number }>();
  const scopedTypes = new Set<string>(["DbContext"]);

  for (const file of csFiles) {
    const code = maskCode(file.content, "csharp");

    for (const m of code.matchAll(CS_SCOPED_REG)) {
      if (m[1]) scopedTypes.add(m[1]);
      if (m[2]) scopedTypes.add(m[2]);
    }
    for (const m of code.matchAll(CS_SINGLETON_REG)) {
      if (m[1]) singletons.set(m[1], { file: file.rel, line: lineOf(file.content, m.index ?? 0) });
    }

    if (/\bUseAuthentication\s*\(/.test(code) || /\bUseAuthorization\s*\(/.test(code)) {
      const positions = new Map<string, number>();
      for (const mw of ASPNET_MW_ORDER) {
        const idx = code.indexOf(`.${mw}(`);
        if (idx >= 0) positions.set(mw, idx);
      }
      const pairs: Array<[string, string]> = [
        ["UseRouting", "UseCors"],
        ["UseRouting", "UseAuthentication"],
        ["UseAuthentication", "UseAuthorization"],
        ["UseAuthorization", "UseAntiforgery"],
        ["UseAuthorization", "MapControllers"],
      ];
      for (const [first, second] of pairs) {
        const p1 = positions.get(first);
        const p2 = positions.get(second);
        if (p1 !== undefined && p2 !== undefined && p1 > p2) {
          push(
            findings, file.rel, lineOf(file.content, p2), "arch-dotnet-middleware-order", "R0", "error",
            `ASP.NET Core middleware order violation: ${second}() is registered before ${first}().`,
            `Order pipeline as UseExceptionHandler -> UseRouting -> UseCors -> UseAuthentication -> UseAuthorization -> UseAntiforgery -> Endpoints.`,
          );
        }
      }
    }

    const validateFalse = /\bValidateScopes\s*=\s*false\b/.exec(code);
    if (validateFalse && validateFalse.index !== undefined) {
      push(
        findings, file.rel, lineOf(file.content, validateFalse.index), "arch-dotnet-di-captive-or-unvalidated-scope", "R1", "error",
        "DI container explicitly disables ValidateScopes = false, hiding captive dependency bugs until production.",
        "Keep ValidateScopes = true and ValidateOnBuild = true in development and test hosts.",
      );
    }
  }

  analyzeDotnetCaptiveDependencies(csFiles, singletons, scopedTypes, findings);
}

function hasWordToken(text: string, token: string): boolean {
  let pos = text.indexOf(token);
  while (pos >= 0) {
    const before = pos > 0 ? text[pos - 1] ?? "" : "";
    const after = pos + token.length < text.length ? text[pos + token.length] ?? "" : "";
    const isWordBefore = /[A-Za-z0-9_]/.test(before);
    const isWordAfter = /[A-Za-z0-9_]/.test(after);
    if (!isWordBefore && !isWordAfter) return true;
    pos = text.indexOf(token, pos + 1);
  }
  return false;
}

const CS_PUBLIC_CTOR = /\bpublic\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/g;

function analyzeDotnetCaptiveDependencies(
  csFiles: readonly ScannedFile[],
  singletons: ReadonlyMap<string, { file: string; line: number }>,
  scopedTypes: ReadonlySet<string>,
  findings: Finding[],
): void {
  for (const file of csFiles) {
    const code = maskCode(file.content, "csharp");
    for (const m of code.matchAll(CS_PUBLIC_CTOR)) {
      const ctorName = m[1] ?? "";
      const params = m[2] ?? "";
      const reg = singletons.get(ctorName);
      if (!reg || !params) continue;
      for (const scoped of scopedTypes) {
        if (hasWordToken(params, scoped)) {
          push(
            findings, file.rel, lineOf(file.content, m.index ?? 0), "arch-dotnet-di-captive-or-unvalidated-scope", "R0", "error",
            `Captive dependency: Singleton '${ctorName}' (registered at ${reg.file}:${reg.line}) injects scoped service '${scoped}'.`,
            "Inject IServiceScopeFactory and create a per-operation scope (CreateAsyncScope) instead of capturing a scoped dependency.",
          );
        }
      }
    }
  }
}

export function analyzeBlackHoleArchGates(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];

  analyzeTsCrossFileGraph(repo, findings);
  analyzeDotnetArchGates(repo, findings);

  for (const file of repo.files) {
    if (!file.language || file.isTest) continue;
    const raw = file.content;
    const code = maskCode(raw, file.language);

    if ((file.language === "typescript" || file.language === "javascript") && SSR_ROUTE_PATH.test(file.rel) && SSR_HANDLER_EXPORT.test(code)) {
      for (const m of code.matchAll(MODULE_MUTABLE_DECL)) {
        const varName = m[1] ?? m[2] ?? "";
        if (!varName) continue;
        const handlerIdx = code.search(SSR_HANDLER_EXPORT);
        const handlerTail = code.slice(handlerIdx);
        const mutated =
          handlerTail.includes(`${varName}.set(`) ||
          handlerTail.includes(`${varName}.push(`) ||
          handlerTail.includes(`${varName}.add(`) ||
          handlerTail.includes(`${varName}.delete(`) ||
          handlerTail.includes(`${varName} = `);
        if (mutated) {
          push(
            findings, file.rel, lineOf(raw, m.index ?? 0), "arch-ssr-module-mutable-state", "R0", "error",
            `Module-level mutable variable '${varName}' is mutated inside an SSR request handler, leaking state across concurrent users.`,
            "Bind per-request caches, auth, and locale state to request/AsyncLocalStorage scope instead of module globals.",
          );
        }
      }
    }

    if (file.language === "typescript" || file.language === "javascript") {
      for (const m of code.matchAll(AGENT_PENDING_MAP)) {
        const idx = m.index ?? 0;
        const mapName = m[1] ?? "";
        const hasCleanup =
          /\bfinally\b/.test(code) ||
          code.includes(`${mapName}.clear(`) ||
          code.includes(`${mapName}.delete(`) ||
          code.includes(`${mapName}.forEach(`);
        if (!hasCleanup) {
          push(
            findings, file.rel, lineOf(raw, idx), "arch-agent-sse-rpc-leak-and-scrub-order", "R1", "warn",
            `Pending RPC/stream map '${mapName}' inserts entries without a finally/EOF rejection cleanup path.`,
            "Reject and clear all pending entries in finally / stream 'close' handlers so premature SSE EOF never hangs callers.",
          );
        }
      }

      for (const m of code.matchAll(SECRET_SCRUB_LOOP)) {
        const idx = m.index ?? 0;
        const before = code.slice(Math.max(0, idx - 260), idx);
        if (!/\.sort\s*\(/.test(before)) {
          push(
            findings, file.rel, lineOf(raw, idx), "arch-agent-sse-rpc-leak-and-scrub-order", "R1", "warn",
            "Secret redaction loop replaces tokens without sorting secrets longest-first, leaking suffixes when one secret prefixes another.",
            "Sort secrets by descending length before iterating replacements across text, thinking, tool args, and errors.",
          );
        }
      }
    }

    if (file.language === "python") {
      for (const m of code.matchAll(CELERY_ACKS_LATE)) {
        const idx = m.index ?? 0;
        const visMatch = /\bvisibility_timeout["']?\s*[:=]\s*(\d+)/.exec(raw);
        const limMatch = /\b(?:task_time_limit|time_limit)\s*[:=]\s*(\d+)/.exec(raw);
        if (visMatch && limMatch && Number(visMatch[1]) <= Number(limMatch[1])) {
          push(
            findings, file.rel, lineOf(raw, idx), "arch-celery-ack-visibility-invariant", "R0", "error",
            `Celery visibility_timeout (${visMatch[1]}s) <= task_time_limit (${limMatch[1]}s) with acks_late=True causes duplicate redelivery of live tasks.`,
            "Set broker visibility_timeout strictly greater than max(task_time_limit, max_eta_countdown) and enforce task idempotency.",
          );
        }
      }
    }

    if (file.language === "go") {
      for (const m of code.matchAll(K8S_LISTER_GET)) {
        const idx = m.index ?? 0;
        const obj = m[1] ?? "";
        if (!obj) continue;
        const after = code.slice(idx + m[0].length, idx + m[0].length + 450);
        const mutatesField =
          after.includes(`${obj}.Labels`) ||
          after.includes(`${obj}.Annotations`) ||
          after.includes(`${obj}.Spec.`) ||
          after.includes(`${obj}.Status.`);
        if (mutatesField && after.includes("=") && !after.includes("DeepCopy()")) {
          push(
            findings, file.rel, lineOf(raw, idx), "arch-k8s-informer-mutate-without-deepcopy", "R0", "error",
            `Informer/lister cache object '${obj}' is mutated directly without .DeepCopy(), corrupting the shared client-go cache.`,
            `Call '${obj} = ${obj}.DeepCopy()' before mutating Labels, Annotations, Spec, or Status.`,
          );
        }
      }
    }
  }

  return findings;
}
