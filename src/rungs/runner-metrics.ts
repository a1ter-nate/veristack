import { extractToolHead, parseAndValidateCommandArgv } from "./command-audit.ts";
import type { RungId } from "../types.ts";

const TEST_RUNNER_HEADS = new Set([
  "vitest", "jest", "mocha", "ava", "pytest", "phpunit", "rspec", "unittest",
  "bun test", "node --test", "dotnet test", "cargo test", "cargo nextest", "go test",
  "playwright", "cypress",
]);

export function hasTestRunnerCommand(rung: RungId | "canary", command: string, repoRoot?: string): boolean {
  const parsed = parseAndValidateCommandArgv(rung, command, repoRoot);
  if (parsed.error) return false;
  return [...detectRunnerHeads(parsed.steps)].some((h) => TEST_RUNNER_HEADS.has(h));
}

export function stripAnsi(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 27 && text[i + 1] === "[") {
      i += 2;
      while (i < text.length) {
        const c = text.charCodeAt(i);
        if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) break;
        i += 1;
      }
      continue;
    }
    out += text[i] ?? "";
  }
  return out;
}

function sumMatches(text: string, regex: RegExp): { found: boolean; sum: number } {
  let found = false;
  let sum = 0;
  for (const m of text.matchAll(regex)) {
    if (m[1] !== undefined) {
      found = true;
      sum += Number(m[1]);
    }
  }
  return { found, sum };
}

function detectRunnerHeads(steps: readonly string[][]): Set<string> {
  const heads = new Set<string>();
  for (const seg of steps) {
    const { head } = extractToolHead(seg);
    if (head) heads.add(head);
  }
  return heads;
}

export function parseRunnerTestCounts(
  rawOutput: string,
  steps: readonly string[][],
): { passed: number; failed: number; matched: boolean; hasTestRunner: boolean } {
  const output = stripAnsi(rawOutput);
  const heads = detectRunnerHeads(steps);
  const hasTestRunner = [...heads].some((h) => TEST_RUNNER_HEADS.has(h));
  let passed = 0;
  let failed = 0;
  let matched = false;

  if (heads.has("cargo test")) {
    const p = sumMatches(output, /test result:\s*(?:ok|FAILED)\.\s*(\d+)\s+passed/gi);
    const f = sumMatches(output, /test result:[^;\n]*?(\d+)\s+failed/gi);
    if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("cargo nextest")) {
    const m = /Summary\s+\[[^\]]+\]\s+(\d+)\s+tests?\s+run:\s+(\d+)\s+passed(?:\s*\([^)]*\))?(?:,\s*(\d+)\s+failed)?/i.exec(output);
    if (m?.[2]) { passed += Number(m[2]); failed += Number(m[3] ?? 0); matched = true; }
  }
  if (heads.has("bun test")) {
    const tail = output.split(/\r?\n/).slice(-12).join("\n");
    const ranLine = /Ran\s+(\d+)\s+tests?\s+across\s+\d+\s+files?/i.exec(tail);
    const p = /^\s*(\d+)\s+pass$/m.exec(tail);
    const f = /^\s*(\d+)\s+fail$/m.exec(tail);
    if (ranLine && (p || f)) {
      passed += Number(p?.[1] ?? 0); failed += Number(f?.[1] ?? 0); matched = true;
    } else if (p || f) {
      passed += Number(p?.[1] ?? 0); failed += Number(f?.[1] ?? 0); matched = true;
    }
  }
  if (heads.has("node --test")) {
    const p = sumMatches(output, /^\s*(?:ℹ|#)\s*pass\s+(\d+)\s*$/gm);
    const f = sumMatches(output, /^\s*(?:ℹ|#)\s*fail\s+(\d+)\s*$/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("vitest") || heads.has("jest")) {
    const p = sumMatches(output, /^\s*Tests:?\s+[^\n]*?(\d+)\s+passed\b/gm);
    const f = sumMatches(output, /^\s*Tests:?\s+[^\n]*?(\d+)\s+failed\b/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("pytest")) {
    const summaryLines = output.split(/\r?\n/).filter((l) => /^=+\s+.*(?:passed|failed|error).*=+$|^\s*\d+\s+(?:passed|failed|errors?)\b.*\bin\s+\d/i.test(l.trim()));
    const scope = summaryLines.join("\n");
    const p = sumMatches(scope, /\b(\d+)\s+passed\b/gi);
    const f = sumMatches(scope, /\b(\d+)\s+(?:failed|errors?)\b/gi);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("unittest")) {
    const ran = /^Ran\s+(\d+)\s+tests?\s+in\b/m.exec(output);
    if (ran?.[1]) {
      const total = Number(ran[1]);
      const failLine = /^FAILED\s*\(([^)]+)\)/m.exec(output);
      if (failLine?.[1]) {
        let fSum = 0;
        for (const fm of failLine[1].matchAll(/(?:failures|errors)=(\d+)/g)) fSum += Number(fm[1] ?? 0);
        failed += Math.max(1, fSum);
        passed += Math.max(0, total - failed);
        matched = true;
      } else if (/^OK\b/m.test(output)) {
        passed += total;
        matched = true;
      }
    }
  }
  if (heads.has("dotnet test")) {
    const p = sumMatches(output, /\b(?:Passed|succeeded):\s*(\d+)/gi);
    const f = sumMatches(output, /\b(?:Failed|failed):\s*(\d+)/gi);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("go test")) {
    let jsonPass = 0; let jsonFail = 0;
    for (const line of output.split(/\r?\n/)) {
      const t = line.trim();
      if (!t.startsWith("{") || !t.endsWith("}")) continue;
      try {
        const ev = JSON.parse(t) as { Action?: string; Test?: string };
        if (ev.Test && ev.Action === "pass") jsonPass += 1;
        else if (ev.Test && ev.Action === "fail") jsonFail += 1;
      } catch { continue; }
    }
    const goVerbose = (output.match(/^---\s+PASS:/gm) ?? []).length;
    const goVerboseFail = (output.match(/^---\s+FAIL:/gm) ?? []).length;
    let goPkg = 0;
    for (const line of output.split(/\r?\n/)) {
      if (/^ok\s+\S+/.test(line) && !/\[no tests to run\]/i.test(line)) goPkg += 1;
    }
    const goFail = (output.match(/^FAIL\s+\S+/gm) ?? []).length;
    if (jsonPass > 0 || jsonFail > 0) {
      passed += jsonPass; failed += jsonFail; matched = true;
    } else if (goVerbose > 0 || goPkg > 0 || goFail > 0 || goVerboseFail > 0) {
      passed += goVerbose > 0 ? goVerbose : goPkg;
      failed += Math.max(goFail, goVerboseFail);
      matched = true;
    }
  }
  if (heads.has("mocha")) {
    const p = sumMatches(output, /^\s*(\d+)\s+passing\b/gm);
    const f = sumMatches(output, /^\s*(\d+)\s+failing\b/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("ava")) {
    const p = sumMatches(output, /^\s*(\d+)\s+tests?\s+passed\b/gm);
    const f = sumMatches(output, /^\s*(\d+)\s+tests?\s+failed\b/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("phpunit")) {
    const p = sumMatches(output, /OK\s*\((\d+)\s+tests?/gi);
    const f = sumMatches(output, /FAILURES![\s\S]{0,80}Failures:\s*(\d+)/gi);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("rspec")) {
    const m = /(\d+)\s+examples?,\s*(\d+)\s+failures?/i.exec(output);
    if (m?.[1]) {
      const fCount = Number(m[2] ?? 0);
      passed += Math.max(0, Number(m[1]) - fCount);
      failed += fCount;
      matched = true;
    }
  }
  if (heads.has("playwright")) {
    const tail = output.split(/\r?\n/).slice(-15).join("\n");
    const p = sumMatches(tail, /^\s*(\d+)\s+passed\s*\(/gm);
    const f = sumMatches(tail, /^\s*(\d+)\s+failed\b/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  if (heads.has("cypress")) {
    const p = sumMatches(output, /^\s*(\d+)\s+passing\b|\bPassing:\s*(\d+)/gm);
    const f = sumMatches(output, /^\s*(\d+)\s+failing\b|\bFailing:\s*(\d+)/gm);
    if (p.found || f.found) { passed += p.sum; failed += f.sum; matched = true; }
  }
  return { passed, failed, matched, hasTestRunner };
}
