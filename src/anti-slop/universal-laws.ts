import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const TERMINAL_STATES =
  "(?:Shipped|Completed|Cancelled|Canceled|Closed|Refunded|Archived|Settled|Terminated|Finalized|Deleted|Disposed)";
const NON_TERMINAL_STATES =
  "(?:Pending|Draft|Open|Queued|Processing|Active|Running|InProgress|Created|Submitted|New)";

const TERMINAL_CASE_RESURRECT = new RegExp(
  `\\bcase\\b[^\\n:;{=>]{0,40}["']?\\b${TERMINAL_STATES}\\b["']?[^\\n{]{0,30}[:=>]\\s*(?:return\\s+)?(?:new\\s+)?["']?[A-Za-z0-9_.:]*(?:\\.|::)?${NON_TERMINAL_STATES}\\b["']?`,
  "g",
);

const RUST_MATCH_TERMINAL_RESURRECT = new RegExp(
  `\\b[A-Za-z0-9_:]*::${TERMINAL_STATES}\\b[^\\n=>]{0,30}=>\\s*(?:Ok\\s*\\(\\s*)?[A-Za-z0-9_:]*::${NON_TERMINAL_STATES}\\b`,
  "g",
);

const NON_NEG_COUNTER =
  "(?:balance|credits|creditBalance|stock|inventory|remaining|quota|allowance|available|budget|availableStock|remainingBudget|remainingQuota)";
const UNGUARDED_COUNTER_SUB = new RegExp(
  `\\b(${NON_NEG_COUNTER})\\s*(?:-=|=\\s*\\1\\s*-)\\s*([A-Za-z_][A-Za-z0-9_.]*)`,
  "g",
);
const SATURATING_OR_GUARD =
  /\b(?:Math\.max\s*\(\s*0|Math\.Clamp|saturating_sub|checked_sub|max\s*\(\s*0|clamp|>=|<=|>|<|throw\b|raise\b|return\s+(?:Err|null|false|undefined)|InvalidOperationException|ArgumentOutOfRangeException)\b/;

const ZERO_CAP_OR_FALLBACK_JS =
  /\b(cap|limit|maxRetries|maxAttempts|maxItems|maxCount|maxConcurrency|quota|budget|pageSize)\s*\|\|\s*(?:[1-9]\d*|[A-Za-z_][A-Za-z0-9_]*)\b/g;
const ZERO_CAP_OR_FALLBACK_PY =
  /\b(cap|limit|max_retries|max_attempts|max_items|max_count|quota|budget|page_size)\s+or\s+(?:[1-9]\d*|[A-Za-z_][A-Za-z0-9_]*)\b/g;

const ENCODE_FN =
  /\b(?:function|def|fn|func|public\s+(?:static\s+)?[A-Za-z0-9_<>,.?]+\s+)\s*(encode[A-Za-z0-9_]*|serialize[A-Za-z0-9_]*|to_wire[A-Za-z0-9_]*|toWire[A-Za-z0-9_]*)\s*\(/g;
const DECODE_FN =
  /\b(?:function|def|fn|func|public\s+(?:static\s+)?[A-Za-z0-9_<>,.?]+\s+)\s*(decode[A-Za-z0-9_]*|deserialize[A-Za-z0-9_]*|from_wire[A-Za-z0-9_]*|fromWire[A-Za-z0-9_]*)\s*\(/g;

const UNPAIRED_LOCK_CS_GO_PY: ReadonlyArray<{ open: RegExp; close: RegExp; label: string }> = [
  { open: /\b([A-Za-z_][A-Za-z0-9_.]*)\.(?:EnterWriteLock|EnterReadLock|Acquire|Wait)\s*\(/g, close: /\.(?:ExitWriteLock|ExitReadLock|Release)\s*\(/, label: "lock/semaphore" },
  { open: /\b([A-Za-z_][A-Za-z0-9_.]*)\.(?:Lock|RLock)\s*\(\s*\)/g, close: /\.(?:Unlock|RUnlock)\s*\(\s*\)/, label: "mutex" },
  { open: /\b([A-Za-z_][A-Za-z0-9_.]*)\.acquire\s*\(/g, close: /\.release\s*\(/, label: "lock" },
];

const GO_WALL_CLOCK_SUB = /\btime\.Now\s*\(\s*\)\s*\.\s*Unix(?:Milli|Micro|Nano)?\s*\(\s*\)\s*-\s*[A-Za-z_][A-Za-z0-9_.]*/g;
const GO_TEST_ONLY_EXPORT = /\bfunc\s+[A-Z][A-Za-z0-9_]*(?:ForTesting|TestOnly)\s*\(/g;

interface LawFindingSpec {
  file: ScannedFile;
  offset: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function pushLaw(findings: Finding[], spec: LawFindingSpec): void {
  const line = lineOf(spec.file.content, spec.offset);
  findings.push({
    id: `LAW:${spec.rule}:${spec.file.rel}:${line}`,
    rule: spec.rule,
    category: "structure",
    rung: spec.rung,
    severity: spec.severity,
    file: spec.file.rel,
    line,
    message: spec.message,
    fix: spec.fix,
  });
}

function extractBodySlice(code: string, startIdx: number): string {
  const openBrace = code.indexOf("{", startIdx);
  if (openBrace >= 0 && openBrace - startIdx < 160) {
    let depth = 0;
    for (let i = openBrace; i < Math.min(code.length, openBrace + 3000); i++) {
      if (code[i] === "{") depth += 1;
      else if (code[i] === "}") {
        depth -= 1;
        if (depth === 0) return code.slice(openBrace, i + 1);
      }
    }
  }
  return code.slice(startIdx, Math.min(code.length, startIdx + 1200));
}

function countSwitchArms(body: string, lang: ScannedFile["language"]): number {
  if (lang === "rust") {
    return (body.match(/=>/g)?.length ?? 0) - (body.match(/\b_\s*=>/g)?.length ?? 0);
  }
  const cases = body.match(/\bcase\b/g)?.length ?? 0;
  if (cases > 0) return cases;
  if (lang === "csharp") {
    return (body.match(/=>/g)?.length ?? 0) - (body.match(/\b_\s*=>/g)?.length ?? 0);
  }
  return 0;
}

function checkTerminalAndCounterLaws(file: ScannedFile, code: string, findings: Finding[]): void {
  const resurrectRe = file.language === "rust" ? RUST_MATCH_TERMINAL_RESURRECT : TERMINAL_CASE_RESURRECT;
  for (const m of file.content.matchAll(resurrectRe)) {
    const idx = m.index ?? 0;
    if (code[idx] === " ") continue;
    pushLaw(findings, {
      file, offset: idx, rule: "law-monotonic-terminal-state", rung: "R1", severity: "error",
      message: "Transition reverts a terminal state back to a non-terminal state (violates Bend 2 monotonic terminal-state law).",
      fix: "Keep terminal states absorbing (return the terminal state unchanged or return a typed rejection error).",
    });
  }
  for (const m of code.matchAll(UNGUARDED_COUNTER_SUB)) {
    const idx = m.index ?? 0;
    if (SATURATING_OR_GUARD.test(code.slice(Math.max(0, idx - 220), idx + 180))) continue;
    pushLaw(findings, {
      file, offset: idx, rule: "law-saturating-underflow", rung: "R1", severity: "warn",
      message: `Unguarded subtraction on non-negative counter '${m[1]}' can underflow below zero (violates Bend 2 sat_sub_zero_left law).`,
      fix: "Use total saturating arithmetic (Math.max(0, ...), saturating_sub, Math.Clamp) or validate amount <= available first.",
    });
  }
}

function checkZeroCapAndCodecLaws(file: ScannedFile, code: string, findings: Finding[]): void {
  if (!code) return;
  const zeroCapRe =
    file.language === "python"
      ? ZERO_CAP_OR_FALLBACK_PY
      : file.language === "typescript" || file.language === "javascript"
        ? ZERO_CAP_OR_FALLBACK_JS
        : null;
  if (zeroCapRe) {
    for (const m of code.matchAll(zeroCapRe)) {
      const idx = m.index ?? 0;
      const lineStart = code.lastIndexOf("\n", idx) + 1;
      const lineEnd = code.indexOf("\n", idx);
      const lineText = code.slice(lineStart, lineEnd >= 0 ? lineEnd : code.length);
      if (/\b(?:if|while)\s*\(/.test(lineText) || /\breturn\s+[^\n]*[=<>!]/.test(lineText)) continue;
      if (file.language === "python" && /^\s*(?:if|elif|while|assert)\b/.test(lineText)) continue;
      pushLaw(findings, {
        file, offset: idx, rule: "law-zero-cap-clamp", rung: "R1", severity: "warn",
        message: `Truthy fallback on cap/limit '${m[1]}' silently overrides an explicit 0 cap (violates Bend 2 clamp_respects_zero_cap law).`,
        fix: file.language === "python"
          ? `Check 'if ${m[1]} is None:' instead of '${m[1]} or ...' so 0 stays 0.`
          : `Use nullish coalescing ('${m[1]} ?? defaultVal') instead of '${m[1]} || defaultVal' so 0 stays 0.`,
      });
    }
  }
  const encodeMatches = [...code.matchAll(ENCODE_FN)];
  const decodeMatches = [...code.matchAll(DECODE_FN)];
  const enc = encodeMatches.length === 1 ? encodeMatches[0] : undefined;
  const dec = decodeMatches.length === 1 ? decodeMatches[0] : undefined;
  if (!enc || !dec) return;
  const encArms = countSwitchArms(extractBodySlice(code, enc.index ?? 0), file.language);
  const decArms = countSwitchArms(extractBodySlice(code, dec.index ?? 0), file.language);
  if (Math.max(encArms, decArms) >= 3 && encArms > 0 && decArms > 0 && encArms !== decArms) {
    pushLaw(findings, {
      file, offset: dec.index ?? 0, rule: "law-codec-roundtrip-asymmetry", rung: "R1", severity: "warn",
      message: `Codec pair '${enc[1]}' (${encArms} branches) and '${dec[1]}' (${decArms} branches) handle different variant counts (violates Bend 2 status_roundtrip law).`,
      fix: "Handle identical variant sets in encode and decode (or derive both from one lookup table) and add a round-trip test.",
    });
  }
}

function isSimpleGoLockSpan(after: string, matchLen: number, closeRe: RegExp): boolean {
  if (/\bdefer\b/.test(after)) return true;
  const unlockPos = after.search(closeRe);
  if (unlockPos <= 0 || unlockPos >= 160) return false;
  const between = after.slice(matchLen, unlockPos);
  const onlyLockedCall = /^[A-Za-z0-9_.\s:=(),;]*Locked\s*\([^)]*\)\s*;?\s*$/.test(between.trim());
  return !/\b(?:return|if|for|switch|panic|go)\b/.test(between) && (!/\w+\s*\(/.test(between) || onlyLockedCall);
}

function checkUnpairedLocksAndGoLaws(file: ScannedFile, code: string, findings: Finding[]): void {
  if (!code) return;
  if (file.language === "csharp" || file.language === "go" || file.language === "python") {
    for (const pair of UNPAIRED_LOCK_CS_GO_PY) {
      for (const m of code.matchAll(pair.open)) {
        const idx = m.index ?? 0;
        const target = m[1] ?? "";
        const after = code.slice(idx, Math.min(code.length, idx + 900));
        if (!pair.close.test(after)) continue;
        if (file.language === "go" && isSimpleGoLockSpan(after, m[0].length, pair.close)) continue;
        if ((file.language === "csharp" || file.language === "python") && /\b(?:finally|using|with)\b/.test(code.slice(Math.max(0, idx - 60), idx + 900))) continue;
        pushLaw(findings, {
          file, offset: idx, rule: "law-unwind-unpaired", rung: "R1", severity: "warn",
          message: `Paired ${pair.label} acquisition on '${target}' lacks try/finally or defer cleanup (violates Bend 2 unwind_restores_empty law).`,
          fix: file.language === "go"
            ? `Call 'defer ${target}.Unlock()' immediately after acquiring the lock.`
            : "Wrap the critical section in try/finally (or a scoped using/with guard) so cleanup runs on every unwind path.",
        });
        break;
      }
    }
  }
  if (file.language !== "go") return;
  for (const m of code.matchAll(GO_WALL_CLOCK_SUB)) {
    pushLaw(findings, {
      file, offset: m.index ?? 0, rule: "cdc-wall-clock-duration", rung: "R1", severity: "warn",
      message: `Wall-clock Unix timestamp subtraction (${m[0].trim()}) breaks on NTP clock jumps (V30 Clock CDC).`,
      fix: "Use time.Since(start) or time.Now().Sub(start) which reads Go's monotonic clock.",
    });
  }
  for (const m of code.matchAll(GO_TEST_ONLY_EXPORT)) {
    pushLaw(findings, {
      file, offset: m.index ?? 0, rule: "no-test-only-production-seam", rung: "R1", severity: "warn",
      message: `Test-only exported function in Go production file: ${m[0].trim()}.`,
      fix: "Remove test-only exports and verify behavior through the public package interface.",
    });
  }
}

export function analyzeUniversalBendLaws(file: ScannedFile): Finding[] {
  if (!file.language || file.isTest) return [];
  const findings: Finding[] = [];
  const code = maskCode(file.content, file.language, true);
  checkTerminalAndCounterLaws(file, code, findings);
  checkZeroCapAndCodecLaws(file, code, findings);
  checkUnpairedLocksAndGoLaws(file, code, findings);
  return findings;
}
