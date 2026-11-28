import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import {
  anonymizeSnippet,
  buildIssueUrl,
  buildToolReport,
  flushLocalFeedbackQueue,
  formatInitReport,
  formatSingleFileReport,
  handleReportCli,
  harnessesPlugin,
  initVeristackRepo,
  manageHooks,
  redactReportText,
  runDoctor,
  scanSingleFile,
  type GhRunner,
} from "@veristack/plugin-harnesses";

test("harnesses plugin defines valid Veristack plugin and registers into harnesses", () => {
  assert.equal(isVeristackPlugin(harnessesPlugin), true);
  assert.equal(harnessesPlugin.id, "veristack.plugin.harnesses");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [harnessesPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.harnesses().length >= 1);
});

test("initVeristackRepo and manageHooks honor dryRun without mutating disk", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-dryrun-"));
  try {
    fs.writeFileSync(path.join(dir, "index.ts"), "export const ready = true;\n");
    const initRes = initVeristackRepo(dir, { dryRun: true });
    assert.equal(initRes.dryRun, true);
    assert.equal(initRes.manifestCreated, true);
    assert.equal(initRes.hooksEnabled, true);
    assert.ok(initRes.touchedFiles.includes(".verification/rungs.json"));
    assert.ok(initRes.touchedFiles.includes(".gitignore"));
    assert.ok(initRes.touchedFiles.includes(".verification/hooks.json"));
    assert.match(formatInitReport(initRes), /dry-run/i);
    assert.deepEqual(fs.readdirSync(dir), ["index.ts"]);

    const hooksOnRes = manageHooks(dir, "on", { dryRun: true, harnesses: ["claude", "cursor"] });
    assert.equal(hooksOnRes.dryRun, true);
    assert.deepEqual(hooksOnRes.touchedManifests, [".claude/settings.local.json", ".cursor/hooks.json"]);
    assert.deepEqual(fs.readdirSync(dir), ["index.ts"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Tricorder effective FP tracking in doctor and compositional summary cache + AutoFix in check-file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-tricorder-"));
  try {
    fs.mkdirSync(path.join(dir, ".verification"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".verification", "escapes.json"),
      JSON.stringify({
        escapes: [],
        ruleFeedback: [
          { rule: "noisy-rule", dismissed: 3, fixed: 4 },
          { rule: "clean-rule", dismissed: 0, fixed: 10 },
        ],
      }),
    );
    fs.writeFileSync(path.join(dir, "src.ts"), "export const v = (1 as any);\n");
    const doc = runDoctor(dir);
    assert.equal(doc.findings.some((f) => f.id === "DOC:high-fp-rule:noisy-rule"), true);
    assert.equal(doc.findings.some((f) => f.id === "DOC:high-fp-rule:clean-rule"), false);

    const first = scanSingleFile(path.join(dir, "src.ts"), { repoRoot: dir });
    const second = scanSingleFile(path.join(dir, "src.ts"), { repoRoot: dir });
    assert.equal(first.findings[0]?.soundness, "incorrectness-witness");
    assert.ok(first.findings[0]?.suggestedFix);
    assert.equal(second.findings.length, first.findings.length);
    assert.ok(formatSingleFileReport(first).includes("AutoFix"));
    assert.ok(formatSingleFileReport(first).includes("False positive or tool bug? Run: vstack report --rule"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("vstack report: path/secret redaction, anonymization, URL clamping, local queue & grouped flush, JSON purity, and gh fallback", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-report-"));
  try {
    const srcFile = path.join(dir, "src", "billing.ts");
    fs.mkdirSync(path.dirname(srcFile), { recursive: true });
    fs.writeFileSync(
      srcFile,
      [
        'const secretToken = "ghp_1234567890abcdef1234567890abcdef";',
        'const dbUrl = "postgres://admin:supersecret@db.internal:5432/prod";',
        'const email = "owner@private-client.example";',
        "export function chargeCustomer(accountId: string): unknown {",
        "  return (accountId as any);",
        "}",
      ].join("\n"),
    );

    const redacted = redactReportText(
      `File ${dir}/src/billing.ts /Users/alice/work /home/bob/p C:\\Users\\carol\\p Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature123 API_KEY=topsecret_val owner@corp.io`,
      dir,
    );
    assert.equal(redacted.includes("alice"), false);
    assert.equal(redacted.includes("bob"), false);
    assert.equal(redacted.includes("carol"), false);
    assert.equal(redacted.includes("topsecret_val"), false);
    assert.equal(redacted.includes("owner@corp.io"), false);
    assert.equal(redacted.includes("signature123"), false);
    assert.ok(redacted.includes("<repo>/src/billing.ts"));

    const anon = anonymizeSnippet('>    4 | export function chargeCustomer(accountId: string) { return callStripe("live_key"); }');
    assert.equal(anon.includes("chargeCustomer"), false);
    assert.equal(anon.includes("accountId"), false);
    assert.equal(anon.includes("live_key"), false);
    assert.match(anon, /fn1\(/);
    assert.match(anon, /"<str>"/);

    const built = buildToolReport({
      repoRoot: dir,
      rule: "no-chained-or-any-cast",
      file: `${srcFile}:5`,
      kind: "fp",
      reason: `Seen at ${dir}/src/billing.ts for owner@private-client.example`,
      anonymize: true,
    });
    assert.equal(built.label, "false-positive");
    assert.equal(built.entry.anonymized, true);
    assert.equal(built.markdown.includes("chargeCustomer"), false);
    assert.equal(built.markdown.includes("ghp_1234567890"), false);
    assert.equal(built.markdown.includes("supersecret"), false);
    assert.equal(built.markdown.includes("owner@private-client.example"), false);
    assert.ok(built.entry.finding?.includes("no-chained-or-any-cast"));

    const noRerunBuilt = buildToolReport({ repoRoot: dir, rule: "no-chained-or-any-cast", file: `${srcFile}:5`, noRerun: true });
    assert.equal(noRerunBuilt.entry.finding, null);

    const clamped = buildIssueUrl({ kind: "fp", title: "[FP] huge", body: "x".repeat(20_000) });
    assert.equal(clamped.truncated, true);
    assert.equal(clamped.url.length <= 7500, true);
    assert.ok(decodeURIComponent(clamped.url).includes("Truncated to fit GitHub URL"));

    const captureLogs = (fn: () => number): { code: number; out: string; err: string } => {
      const outs: string[] = [];
      const errs: string[] = [];
      const origLog = console.log;
      const origErr = console.error;
      console.log = (...a: unknown[]) => { outs.push(a.map(String).join(" ")); };
      console.error = (...a: unknown[]) => { errs.push(a.map(String).join(" ")); };
      try { return { code: fn(), out: outs.join("\n"), err: errs.join("\n") }; }
      finally { console.log = origLog; console.error = origErr; }
    };

    const dry = captureLogs(() => handleReportCli(["--rule", "no-chained-or-any-cast", "--file", `${srcFile}:5`, "--anonymize"], false, dir));
    assert.equal(dry.code, 0);
    assert.ok(dry.out.includes("Dry-run preview"));

    const jsonOut = captureLogs(() => handleReportCli(["--rule", "no-chained-or-any-cast", "--file", `${srcFile}:5`, "--no-rerun", "--json"], true, dir));
    assert.equal(jsonOut.code, 0);
    const parsedJson = JSON.parse(jsonOut.out) as { mode: string; entry: { rule: string } };
    assert.equal(parsedJson.mode, "single");
    assert.equal(parsedJson.entry.rule, "no-chained-or-any-cast");

    const outMd = path.join(dir, "out", "report.md");
    const written = captureLogs(() => handleReportCli(["--rule", "no-chained-or-any-cast", "--file", `${srcFile}:5`, "--out", outMd], false, dir));
    assert.equal(written.code, 0);
    assert.equal(fs.existsSync(outMd), true);

    assert.equal(captureLogs(() => handleReportCli(["--rule", "rule-a", "--file", `${srcFile}:5`, "--reason", "dup", "--local", "--no-rerun"], false, dir)).code, 0);
    assert.equal(captureLogs(() => handleReportCli(["--rule", "rule-a", "--file", `${srcFile}:5`, "--reason", "dup", "--local", "--no-rerun"], false, dir)).code, 0);
    assert.equal(captureLogs(() => handleReportCli(["--rule", "rule-b", "--kind", "bug", "--reason", "other", "--local", "--no-rerun"], false, dir)).code, 0);

    const previewFlush = flushLocalFeedbackQueue({ repoRoot: dir });
    assert.equal(previewFlush.rawCount, 3);
    assert.equal(previewFlush.uniqueCount, 2);
    assert.equal(previewFlush.groups.length, 2);
    assert.equal(previewFlush.cleared, false);
    assert.equal(fs.existsSync(path.join(dir, ".verification", "tool-feedback.jsonl")), true);

    const missingGh: GhRunner = () => ({ status: 1, stdout: "", stderr: "gh not found", error: new Error("ENOENT") });
    const failedSub = captureLogs(() => handleReportCli(["--flush", "--submit"], false, dir, missingGh));
    assert.equal(failedSub.code, 1);
    assert.ok(failedSub.err.includes("GitHub CLI"));
    assert.ok(failedSub.out.includes("https://github.com/a1ter-nate/veristack/issues/new"));
    assert.equal(fs.existsSync(path.join(dir, ".verification", "tool-feedback.jsonl")), true);

    const okGh: GhRunner = (args) => ({ status: 0, stdout: args[0] === "issue" ? "https://github.com/a1ter-nate/veristack/issues/99\n" : "ok\n", stderr: "" });
    const okSub = captureLogs(() => handleReportCli(["--flush", "--submit"], false, dir, okGh));
    assert.equal(okSub.code, 0);
    assert.ok(okSub.out.includes("https://github.com/a1ter-nate/veristack/issues/99"));
    assert.equal(fs.existsSync(path.join(dir, ".verification", "tool-feedback.jsonl")), false);

    assert.equal(captureLogs(() => handleReportCli(["--rule", "rule-c", "--local", "--no-rerun"], false, dir)).code, 0);
    const clearedExplicit = flushLocalFeedbackQueue({ repoRoot: dir, clear: true });
    assert.equal(clearedExplicit.cleared, true);
    assert.equal(fs.existsSync(path.join(dir, ".verification", "tool-feedback.jsonl")), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
