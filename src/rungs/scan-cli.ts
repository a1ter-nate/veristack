import fs from "node:fs";
import { formatMarkdownReport, formatTerminalReport } from "../format.ts";
import { scanRepo } from "../ladder.ts";
import {
  buildRatchetBaseline,
  evaluateRatchet,
  type RatchetBaseline,
  writeRatchetBaseline,
} from "../ratchet.ts";

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index < 0) return undefined;
  return args[index + 1];
}

export function handleScanCli(rest: readonly string[], target: string, asJson: boolean, asMd: boolean): number {
  const strict = rest.includes("--strict");
  const allowMissingRungs = rest.includes("--allow-missing-rungs");
  const failOnPoorCoverage = rest.includes("--fail-on-poor-coverage");
  const configPath = parseFlagValue(rest, "--config");
  const disableRaw = parseFlagValue(rest, "--disable");
  const disableRules = disableRaw
    ? disableRaw.split(",").map((r) => r.trim()).filter(Boolean)
    : undefined;
  const ratchetPath = parseFlagValue(rest, "--ratchet");
  const updateRatchet = rest.includes("--update-ratchet");

  if (strict && (ratchetPath || updateRatchet)) {
    console.error("vstack scan --strict forbids --ratchet and --update-ratchet baselines.");
    return 1;
  }
  if (strict && (configPath || (disableRules && disableRules.length > 0))) {
    console.error("vstack scan --strict forbids --config and --disable rule overrides.");
    return 1;
  }
  if (strict && allowMissingRungs) {
    console.error("vstack scan --strict forbids --allow-missing-rungs.");
    return 1;
  }

  const report = scanRepo(target, { configPath, disableRules });
  let ratchetEval: ReturnType<typeof evaluateRatchet> | undefined;

  if (ratchetPath) {
    if (updateRatchet || !fs.existsSync(ratchetPath)) {
      const nextBaseline = buildRatchetBaseline(report.findings, report.rungs);
      writeRatchetBaseline(ratchetPath, nextBaseline);
      ratchetEval = evaluateRatchet(report.findings, nextBaseline, report.rungs);
    } else {
      const baseline = JSON.parse(fs.readFileSync(ratchetPath, "utf8")) as RatchetBaseline;
      ratchetEval = evaluateRatchet(report.findings, baseline, report.rungs);
    }
  }

  if (asJson) console.log(JSON.stringify(ratchetEval ? { ...report, ratchet: ratchetEval } : report, null, 2));
  else if (asMd) console.log(formatMarkdownReport(report));
  else {
    console.log(formatTerminalReport(report));
    if (ratchetEval) {
      console.log(`\nRATCHET (${ratchetPath}): ${ratchetEval.passed ? "PASS" : "FAIL"}`);
      for (const r of ratchetEval.regressions) {
        console.log(`  - [REGRESSION] ${r.rule}: ${r.baseline} -> ${r.current} (+${r.delta})`);
      }
      for (const t of ratchetEval.tightenAvailable) {
        console.log(`  - [TIGHTEN] ${t.rule}: ${t.baseline} -> ${t.current} (${t.delta}) — rerun with --update-ratchet`);
      }
      for (const rr of ratchetEval.rungRegressions) {
        console.log(`  - [RUNG REGRESSION] ${rr.rung}: ${rr.reason}`);
      }
    }
  }

  const s = report.summary;

  if (strict) {
    if (report.config && (report.config.disabledRules.length > 0 || report.config.suppressedCount > 0)) {
      console.error("vstack scan --strict failed: .vstack.json disables or suppresses rules.");
      return 1;
    }
    if (
      s.totalFindings > 0 ||
      s.errorCount > 0 ||
      s.warnCount > 0 ||
      s.cheatCount > 0 ||
      s.noCommentCount > 0 ||
      s.holeCount > 0 ||
      s.poorlyCoveredCount > 0 ||
      s.unexecutedRungCount > 0 ||
      s.pushDownCount > 0
    ) {
      return 1;
    }
    return 0;
  }

  if (ratchetEval && !ratchetEval.passed) return 1;
  if (!allowMissingRungs && !ratchetEval && (s.holeCount > 0 || s.unexecutedRungCount > 0)) {
    if (!asJson && !asMd) {
      console.error(
        `\nFAIL: ${s.holeCount} not-covered/over-budget rung(s) and ${s.unexecutedRungCount} rung(s) not executing in CI. Wire missing rungs into CI (or pass --allow-missing-rungs for snippet-only scans).`,
      );
    }
    return 1;
  }
  if (failOnPoorCoverage && s.poorlyCoveredCount > 0) return 1;
  if (rest.includes("--fail-on-errors") && s.errorCount > 0) return 1;
  if (rest.includes("--fail-on-cheats") && (s.cheatCount > 0 || s.noCommentCount > 0)) {
    return 1;
  }
  return 0;
}
