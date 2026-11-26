import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { lineOf, maskCode, maskStrings } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated|min|bundle)\.[cm]?[jt]sx?$/i;

const LOOP_START_PAREN = /\b(?:for|while|foreach)\s*(?:await\s*)?\([^)]*\)\s*\{/g;
const LOOP_START_RUST = /(?:^|[;{}]\s*)(?:'[a-zA-Z_][a-zA-Z0-9_]*:\s*)?(?:for\s+[^{;]+\bin\b[^{;]+|while\s+[^{;]+)\s*\{/gm;
const LOOP_START_GO = /(?:^|[;{}]\s*)for\b[^{;]*\{/gm;

const PERF_CHEAT_PATTERN = /\bgc\.disable\s*\(\s*\)|#\s*pragma\s+GCC\s+optimize\b|\bGC\.TryStartNoGCRegion\s*\(/g;

interface LoopSpan {
  start: number;
  body: string;
}

function maskCommentsAndStrings(source: string, isPython: boolean): string {
  const base = maskStrings(source);
  const out = [...base];
  for (let i = 0; i < out.length; i++) {
    const ch = out[i];
    const next = out[i + 1];
    if (isPython && ch === "#") {
      while (i < out.length && out[i] !== "\n") {
        out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (!isPython && ch === "/" && next === "/") {
      while (i < out.length && out[i] !== "\n") {
        out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (!isPython && ch === "/" && next === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < out.length) {
        if (out[i] === "*" && out[i + 1] === "/") {
          out[i] = " ";
          out[i + 1] = " ";
          i += 1;
          break;
        }
        if (out[i] !== "\n") out[i] = " ";
        i += 1;
      }
    }
  }
  return out.join("");
}

function extractBraceLoopSpans(masked: string, language: ScannedFile["language"]): LoopSpan[] {
  const spans: LoopSpan[] = [];
  const loopRegex =
    language === "rust" ? LOOP_START_RUST : language === "go" ? LOOP_START_GO : LOOP_START_PAREN;
  for (const match of masked.matchAll(loopRegex)) {
    const start = match.index ?? 0;
    const openBrace = start + match[0].length - 1;
    let depth = 0;
    let end = openBrace;
    for (let i = openBrace; i < masked.length; i++) {
      const ch = masked[i];
      if (ch === "{") depth += 1;
      else if (ch === "}") {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end > openBrace) {
      spans.push({ start: openBrace, body: masked.slice(openBrace, end + 1) });
    }
  }
  return spans;
}

function extractPythonLoopSpans(masked: string): LoopSpan[] {
  const spans: LoopSpan[] = [];
  const lines = masked.split(/\r?\n/);
  const offsets: number[] = [];
  let cursor = 0;
  for (const l of lines) {
    offsets.push(cursor);
    cursor += l.length + 1;
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const m = /^(\s*)(?:async\s+)?(?:for|while)\b[^:\n]*:\s*$/.exec(line);
    if (!m) continue;
    const baseIndent = (m[1] ?? "").length;
    let endLine = i;
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j] ?? "";
      const trimmed = next.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const ind = next.length - next.trimStart().length;
      if (ind <= baseIndent) break;
      endLine = j;
    }
    if (endLine > i) {
      const start = offsets[i + 1] ?? 0;
      const body = lines.slice(i + 1, endLine + 1).join("\n");
      spans.push({ start, body });
    }
  }
  return spans;
}

function checkLoopRules(file: ScannedFile, raw: string, masked: string): Finding[] {
  const findings: Finding[] = [];
  const seenLines = new Set<string>();
  const spans =
    file.language === "python" ? extractPythonLoopSpans(masked) : extractBraceLoopSpans(masked, file.language);

  const pushOnce = (rule: string, offset: number, message: string, fix: string): void => {
    const line = lineOf(raw, offset);
    const key = `${rule}:${line}`;
    if (seenLines.has(key)) return;
    seenLines.add(key);
    findings.push({
      id: `PF:${rule}:${file.rel}:${line}`,
      rule,
      category: "structure",
      rung: "R1",
      severity: "warn",
      file: file.rel,
      line,
      message,
      fix,
    });
  };

  const quadPattern =
    file.language === "typescript" || file.language === "javascript"
      ? /\.\s*(?:shift|unshift)\s*\(\s*\)|\.\s*splice\s*\(\s*0\b|\.\s*(?:find|findIndex)\s*\(/g
      : file.language === "python"
        ? /\.\s*pop\s*\(\s*0\s*\)|\.\s*insert\s*\(\s*0\s*,/g
        : file.language === "csharp"
          ? /\.\s*RemoveAt\s*\(\s*0\s*\)|\.\s*Insert\s*\(\s*0\s*,|\.\s*(?:FirstOrDefault|SingleOrDefault)\s*\(/g
          : file.language === "rust"
            ? /\.\s*remove\s*\(\s*0\s*\)|\.\s*insert\s*\(\s*0\s*,|\.\s*iter\s*\(\s*\)\s*\.\s*(?:find|position)\s*\(/g
            : undefined;

  const nplus1Pattern =
    file.language === "typescript" || file.language === "javascript"
      ? /\bawait\s+(?:fetch\s*\(|(?:db|pool|client|prisma|tx|knex)\s*\.[a-zA-Z0-9_.]+\s*\()/g
      : file.language === "python"
        ? /\b(?:cursor|conn|session)\s*\.\s*execute\s*\(|\b(?:requests|httpx)\s*\.\s*(?:get|post|put|delete)\s*\(/g
        : file.language === "csharp"
          ? /\bawait\s+[A-Za-z0-9_.]+\.(?:SingleAsync|SingleOrDefaultAsync|FirstAsync|FirstOrDefaultAsync|ExecuteReaderAsync|GetAsync|SendAsync)\s*\(/g
          : file.language === "rust"
            ? /\bsqlx::query(?:_as)?!?\s*\(|\.\s*(?:fetch_one|fetch_all|fetch_optional)\s*\(|\breqwest::(?:get|Client::new)\s*\(/g
            : undefined;

  const compileCopyPattern =
    file.language === "typescript" || file.language === "javascript"
      ? /\bnew\s+RegExp\s*\(|\bJSON\.parse\s*\(\s*JSON\.stringify\s*\(/g
      : file.language === "python"
        ? /\bre\.compile\s*\(|\bcopy\.deepcopy\s*\(/g
        : file.language === "csharp"
          ? /\bnew\s+Regex\s*\(/g
          : file.language === "rust"
            ? /\bRegex::new\s*\(/g
            : undefined;

  for (const span of spans) {
    if (quadPattern) {
      for (const m of span.body.matchAll(quadPattern)) {
        pushOnce(
          "perf-quadratic-loop-scan",
          span.start + (m.index ?? 0),
          `Potential O(N^2) collection operation inside loop (${m[0].trim()}).`,
          "Index lookups with a Set/HashSet/Map/dict or use an O(1) deque/ring-buffer instead of scanning or shifting inside a loop.",
        );
      }
    }
    if (nplus1Pattern) {
      for (const m of span.body.matchAll(nplus1Pattern)) {
        pushOnce(
          "perf-nplus1-io-in-loop",
          span.start + (m.index ?? 0),
          `Potential N+1 database/network I/O call inside loop (${m[0].trim()}).`,
          "Batch queries with IN (...)/JOIN or bounded concurrent batching outside the loop.",
        );
      }
    }
    if (compileCopyPattern) {
      for (const m of span.body.matchAll(compileCopyPattern)) {
        pushOnce(
          "perf-loop-compile-or-deepcopy",
          span.start + (m.index ?? 0),
          `Repeated regex compilation or deep copy inside loop (${m[0].trim()}).`,
          "Hoist compiled regular expressions to module/static scope and avoid per-iteration deep clones.",
        );
      }
    }
  }

  return findings;
}

export function analyzePerfHygiene(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    if (!file.language || GENERATED_PATH.test(file.rel)) continue;
    const raw = file.content;
    const masked = maskCommentsAndStrings(raw, file.language === "python");

    for (const m of masked.matchAll(PERF_CHEAT_PATTERN)) {
      const line = lineOf(raw, m.index ?? 0);
      findings.push({
        id: `PF:cheat:${file.rel}:${line}`,
        rule: "perf-anti-cheat",
        category: "cheat",
        rung: "R0",
        severity: "error",
        file: file.rel,
        line,
        message: `Performance/GC benchmark tampering detected (${m[0].trim()}).`,
        fix: "Remove GC disabling or compiler-pragma hacks and optimize the real algorithm or data layout.",
      });
    }

    if (file.isTest) continue;
    const prodMasked = file.language === "rust" ? maskCode(raw, "rust", true) : masked;
    findings.push(...checkLoopRules(file, raw, prodMasked));
  }
  return findings;
}
