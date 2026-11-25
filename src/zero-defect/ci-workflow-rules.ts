import type { ScannedFile } from "../discover.ts";
import type { Finding } from "../types.ts";

const TWO_DOT_PR_DIFF = /\bgit\s+diff\b[^\n]*(?:\$\{?[A-Z_]*(?:BASE|MAIN|TARGET)[A-Z0-9_]*\}?|\borigin\/main\b)\s+(?:\$\{?[A-Z_]*(?:HEAD|SHA|COMMIT)[A-Z0-9_]*\}?|\bHEAD\b)/;
const UNBOUNDED_BG_WORKERS = /\b(?:vitest|jest)\b[^\n]*&\s*$|\b--maxWorkers(?:=|\s+)(?:[89]|\d{2,})\b/;
const HARDCODED_LOCAL_PORT =
  /(?:--port(?:=|\s+)|(?:localhost|127\.0\.0\.1):)(?:300\d|417\d|517\d|808\d|809\d|900\d|909\d|919\d|929\d)\b/;
const COMBINED_BUILD_TEST = /\bturbo\s+run\s+build\s+test\b|\bpnpm\s+-r\s+(?:--parallel\s+)?build\s+test\b/;
const MAESTRO_SCROLL_BLOCK = /^\s*-\s*scrollUntilVisible\s*:/gm;

interface JobSpan {
  name: string;
  startLine: number;
  body: string;
}

function parseWorkflowJobs(content: string): JobSpan[] {
  const lines = content.split(/\r?\n/);
  const jobsLine = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (jobsLine < 0) return [];
  const jobs: JobSpan[] = [];
  let current: { name: string; startLine: number; lines: string[] } | null = null;
  for (let i = jobsLine + 1; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (/^[A-Za-z0-9_-]+:\s*/.test(raw)) break;
    const jobHeader = /^  ([A-Za-z0-9_-]+):\s*$/.exec(raw);
    if (jobHeader) {
      if (current) jobs.push({ name: current.name, startLine: current.startLine, body: current.lines.join("\n") });
      current = { name: jobHeader[1] ?? "job", startLine: i + 1, lines: [raw] };
    } else if (current) {
      current.lines.push(raw);
    }
  }
  if (current) jobs.push({ name: current.name, startLine: current.startLine, body: current.lines.join("\n") });
  return jobs;
}

export function auditExtendedCiRules(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx] ?? "";
    const stripped = raw.replace(/\s+#.*$/, "");
    if (!stripped.trim() || /^\s*#/.test(raw)) continue;

    if (TWO_DOT_PR_DIFF.test(stripped) && !stripped.includes("...")) {
      findings.push({
        id: `CI:two-dot-diff:${file.rel}:${idx + 1}`,
        rule: "ci-two-dot-pr-diff",
        category: "ci-hygiene",
        rung: "R0",
        severity: "warn",
        file: file.rel,
        line: idx + 1,
        message: "Two-dot 'git diff BASE HEAD' compares branch tips and flags unrelated base-branch commits in PRs.",
        fix: "Use three-dot merge-base syntax ('git diff BASE...HEAD') for PR changed-file checks.",
      });
    }

    if (UNBOUNDED_BG_WORKERS.test(stripped)) {
      findings.push({
        id: `CI:unbounded-workers:${file.rel}:${idx + 1}`,
        rule: "ci-unbounded-test-workers",
        category: "ci-hygiene",
        rung: "R6",
        severity: "warn",
        file: file.rel,
        line: idx + 1,
        message: "CI step oversubscribes test workers (backgrounded vitest/jest or --maxWorkers >= 8), causing event-loop timeout flakes.",
        fix: "Cap --maxWorkers to runner vCPUs (e.g. 2-4) and avoid parallel background test runners on shared slots.",
      });
    }

    if (HARDCODED_LOCAL_PORT.test(stripped) && !/\$\{?[A-Za-z_]*PORT/.test(stripped)) {
      findings.push({
        id: `CI:static-port:${file.rel}:${idx + 1}`,
        rule: "ci-hardcoded-service-port",
        category: "ci-hygiene",
        rung: "R4",
        severity: "warn",
        file: file.rel,
        line: idx + 1,
        message: "Hardcoded localhost service/emulator port in CI risks cross-slot port collisions on shared runners.",
        fix: "Allocate ports dynamically or parameterize via an environment variable with a per-slot offset.",
      });
    }

    if (COMBINED_BUILD_TEST.test(stripped)) {
      findings.push({
        id: `CI:build-test-wave:${file.rel}:${idx + 1}`,
        rule: "ci-combined-build-test-wave",
        category: "ci-hygiene",
        rung: "R6",
        severity: "warn",
        file: file.rel,
        line: idx + 1,
        message: "Running monorepo build and test concurrently in one command starves runner CPU/RAM and causes timeout flakes.",
        fix: "Separate build and test into sequential steps or cap task concurrency explicitly.",
      });
    }
  }

  if (file.rel.startsWith(".github/workflows/")) {
    const cacheKeyRe = /uses:\s*actions\/cache@[^\n]+[\s\S]{0,400}?\bkey:\s*([^\n]+)/g;
    for (const m of file.content.matchAll(cacheKeyRe)) {
      const keyExpr = m[1] ?? "";
      if (!/hashFiles\s*\(/i.test(keyExpr)) {
        const line = file.content.slice(0, m.index ?? 0).split(/\r?\n/).length;
        findings.push({
          id: `CI:cache-hash:${file.rel}:${line}`,
          rule: "ci-cache-key-missing-hash",
          category: "ci-hygiene",
          rung: "R6",
          severity: "warn",
          file: file.rel,
          line,
          message: "actions/cache key omits hashFiles(...), risking stale dependency/tool cache collisions across updates.",
          fix: "Include hashFiles('**/lockfile...') or a tool-manifest hash in the cache key.",
        });
      }
    }

    const cacheSaveRe = /uses:\s*actions\/cache\/save@[^\n]+/g;
    for (const m of file.content.matchAll(cacheSaveRe)) {
      const idx = m.index ?? 0;
      const before = file.content.slice(Math.max(0, idx - 220), idx);
      if (!/^\s*if\s*:/m.test(before)) {
        const line = file.content.slice(0, idx).split(/\r?\n/).length;
        findings.push({
          id: `CI:cache-save-unscoped:${file.rel}:${line}`,
          rule: "ci-cache-save-unscoped-branch",
          category: "ci-hygiene",
          rung: "R6",
          severity: "warn",
          file: file.rel,
          line,
          message: "Unconditional actions/cache/save lets feature branches overwrite shared caches.",
          fix: "Gate actions/cache/save with an if: condition scoped to the default branch or unique ref.",
        });
      }
    }

    for (const job of parseWorkflowJobs(file.content)) {
      const hasAlways = /^\s*if:\s*.*always\(\)/m.test(job.body);
      const hasNeeds = /^\s*needs:/m.test(job.body);
      const checksNeedsResult = /\bneeds\.[A-Za-z0-9_-]+\.result\b/.test(job.body);
      if (hasAlways && hasNeeds && !checksNeedsResult) {
        findings.push({
          id: `CI:always-gate:${file.rel}:${job.startLine}`,
          rule: "ci-always-without-gate-check",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: file.rel,
          line: job.startLine,
          message: `Job '${job.name}' uses if: always() with needs: but never inspects needs.<id>.result.`,
          fix: "Explicitly verify upstream needs.<id>.result == 'success' (and guard against 'skipped'/'failure') before passing or publishing.",
        });
      }

      const runsBrowser = /\b(?:playwright\s+test|vite\s+preview)\b/i.test(job.body);
      const hasBuildOrDownload = /\b(?:build|download-artifact|playwright-prebuilt|PREBUILT=1)\b/i.test(job.body);
      if (runsBrowser && !hasNeeds && !hasBuildOrDownload) {
        findings.push({
          id: `CI:unbuilt-browser:${file.rel}:${job.startLine}`,
          rule: "ci-unbuilt-browser-consumer",
          category: "ci-hygiene",
          rung: "R4",
          severity: "warn",
          file: file.rel,
          line: job.startLine,
          message: `Browser job '${job.name}' runs Playwright/preview without an upstream build dependency or build step.`,
          fix: "Run the app build step in this job or depend on a build-artifact producer via needs: + download-artifact.",
        });
      }
    }
  }

  return findings;
}

export function auditMaestroFlow(file: ScannedFile): Finding[] {
  if (!/\.ya?ml$/i.test(file.rel)) return [];
  if (!/^\s*appId\s*:/m.test(file.content)) return [];
  const findings: Finding[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const m of file.content.matchAll(MAESTRO_SCROLL_BLOCK)) {
    const startLine = file.content.slice(0, m.index ?? 0).split(/\r?\n/).length;
    const block = lines.slice(startLine - 1, startLine + 8).join("\n");
    if (!/\bcenterElement\s*:\s*true\b/.test(block)) {
      findings.push({
        id: `E2E:maestro-scroll:${file.rel}:${startLine}`,
        rule: "e2e-maestro-unsafe-scroll",
        category: "test-smell",
        rung: "R7",
        severity: "warn",
        file: file.rel,
        line: startLine,
        message: "Maestro scrollUntilVisible omits centerElement: true, causing taps to hit sticky headers or bottom overlays.",
        fix: "Add 'centerElement: true' to scrollUntilVisible blocks and dismiss soft keyboards before bottom-bar taps.",
      });
    }
  }
  return findings;
}
