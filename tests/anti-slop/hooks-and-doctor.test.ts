import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanSingleFile } from "../../src/hooks/check-file.ts";
import { runDoctor } from "../../src/hooks/doctor.ts";
import { manageHooks } from "../../src/hooks/install.ts";
import { executeHookEvent } from "../../src/hooks/runtime.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

test("check-file detects immediate slop in milliseconds and stays clean on valid code", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-checkfile-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    const badPath = path.join(tmp, "src", "bad.ts");
    fs.writeFileSync(
      badPath,
      [
        "// prose excuse comment",
        "export function x(v: unknown) {",
        "  try { return v as unknown as number; } catch {}",
        "}",
      ].join("\n") + "\n",
    );
    const bad = scanSingleFile(badPath, { repoRoot: tmp, tier: "immediate" });
    const rules = new Set(bad.findings.map((f) => f.rule));
    assert.ok(rules.has("no-comments"));
    assert.ok(rules.has("no-chained-or-any-cast"));
    assert.ok(rules.has("no-swallowing-catch"));
    assert.ok(bad.elapsedMs < 2000);

    const goodPath = path.join(tmp, "src", "good.ts");
    fs.writeFileSync(goodPath, "export function add(a: number, b: number): number { return a + b; }\n");
    const good = scanSingleFile(goodPath, { repoRoot: tmp, tier: "all" });
    assert.deepEqual(good.findings, []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("two-tier hooks emit PostToolUse context, deduplicate on Stop, and block Cursor preToolUse writes", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-hooks-rt-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "dev@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "Dev"], { cwd: tmp });
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    const cleanFile = path.join(tmp, "src", "ok.ts");
    fs.writeFileSync(cleanFile, "export const ok = (n: number): number => n + 1;\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    const preAllow = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: tmp, tool_input: { file_path: cleanFile, content: "export const ok = (n: number) => n + 2;\n" } }),
      { harness: "cursor" },
    );
    assert.equal(JSON.parse(preAllow.stdout).permission, "allow");

    const preDeny = executeHookEvent(
      "pre-edit",
      JSON.stringify({ cwd: tmp, tool_input: { file_path: cleanFile, content: "export const bad = (x: unknown) => x as any;\n" } }),
      { harness: "cursor" },
    );
    const denyPayload = JSON.parse(preDeny.stdout);
    assert.equal(denyPayload.permission, "deny");
    assert.match(denyPayload.agent_message, /no-chained-or-any-cast/);

    const cleanPost = executeHookEvent(
      "post-edit",
      JSON.stringify({ cwd: tmp, session_id: "s-clean", tool_input: { file_path: cleanFile } }),
      { harness: "claude" },
    );
    assert.equal(cleanPost.stdout, "");

    const badFile = path.join(tmp, "src", "bad.ts");
    fs.writeFileSync(badFile, "export const bad = (x: unknown) => { try { return x as any; } catch {} };\n");
    const dirtyPost = executeHookEvent(
      "post-edit",
      JSON.stringify({ cwd: tmp, session_id: "s-dirty", tool_input: { file_path: badFile } }),
      { harness: "claude" },
    );
    const postPayload = JSON.parse(dirtyPost.stdout);
    assert.equal(postPayload.hookSpecificOutput.hookEventName, "PostToolUse");
    assert.match(postPayload.hookSpecificOutput.additionalContext, /no-chained-or-any-cast/);

    const unfixedStop = executeHookEvent(
      "stop",
      JSON.stringify({ cwd: tmp, session_id: "s-dirty" }),
      { harness: "claude" },
    );
    assert.equal(JSON.parse(unfixedStop.stdout).decision, "block");

    fs.writeFileSync(badFile, "export const good = (x: number): number => x + 1;\n");
    executeHookEvent(
      "post-edit",
      JSON.stringify({ cwd: tmp, session_id: "s-fixed", tool_input: { file_path: badFile } }),
      { harness: "claude" },
    );
    const cleanStop = executeHookEvent(
      "stop",
      JSON.stringify({ cwd: tmp, session_id: "s-fixed" }),
      { harness: "claude" },
    );
    assert.equal(cleanStop.stdout, "");

    fs.writeFileSync(badFile, "export const bad = (x: unknown) => x as any;\n");
    const grokPost = executeHookEvent(
      "post-edit",
      JSON.stringify({ cwd: tmp, session_id: "s-grok", tool_input: { file_path: badFile } }),
      { harness: "grok" },
    );
    assert.equal(grokPost.stdout, "");
    const grokStop = executeHookEvent(
      "stop",
      JSON.stringify({ cwd: tmp, session_id: "s-grok" }),
      { harness: "grok" },
    );
    assert.match(JSON.parse(grokStop.stdout).additionalContext, /no-chained-or-any-cast/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hooks admin installs/preserves/toggles/resets all 5 harness manifests and doctor reports drift", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-hooks-adm-"));
  try {
    fs.mkdirSync(path.join(tmp, ".claude"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".claude", "settings.local.json"),
      JSON.stringify({ hooks: { PostToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo keep-me" }] }] } }),
    );

    const onRes = manageHooks(tmp, "on", { harnesses: ["claude", "codex", "cursor", "copilot", "grok"] });
    assert.equal(onRes.enabled, true);
    assert.equal(onRes.touchedManifests.length, 5);
    const claudeJson = JSON.parse(fs.readFileSync(path.join(tmp, ".claude", "settings.local.json"), "utf8"));
    assert.equal(claudeJson.hooks.PostToolUse.length, 2);

    const offRes = manageHooks(tmp, "off");
    assert.equal(offRes.enabled, false);
    assert.equal(manageHooks(tmp, "status").enabled, false);

    fs.writeFileSync(path.join(tmp, ".cursor", "hooks.json"), "{ invalid json");
    fs.writeFileSync(path.join(tmp, ".vstack.json"), JSON.stringify({ rules: { "no-comments": "off" } }));
    const doc = runDoctor(tmp);
    assert.equal(doc.healthy, false);
    assert.ok(doc.findings.some((f) => f.level === "auto" && f.artifact === ".cursor/hooks.json"));
    assert.ok(doc.findings.some((f) => f.level === "mention" && f.artifact === ".vstack.json"));

    const resetRes = manageHooks(tmp, "reset");
    assert.equal(resetRes.enabled, false);
    const claudeAfter = JSON.parse(fs.readFileSync(path.join(tmp, ".claude", "settings.local.json"), "utf8"));
    assert.equal(claudeAfter.hooks.PostToolUse.length, 1);
    assert.equal(claudeAfter.hooks.PostToolUse[0].matcher, "Bash");

    const cleanTmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-doc-clean-"));
    try {
      spawnSync("git", ["init", "-q"], { cwd: cleanTmp });
      fs.writeFileSync(path.join(cleanTmp, "index.ts"), "export const x = 1;\n");
      const cliDoc = spawnSync(process.execPath, [binPath, "doctor", cleanTmp, "--json", "--fail"], { encoding: "utf8" });
      assert.equal(cliDoc.status, 0, cliDoc.stdout + cliDoc.stderr);
      assert.equal(JSON.parse(cliDoc.stdout).healthy, true);
    } finally {
      fs.rmSync(cleanTmp, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("doctor rejects weakened hook manifests and root-anchored hooks fire from cd src/", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-doc-pin-"));
  try {
    spawnSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
    spawnSync("git", ["config", "user.name", "Test"], { cwd: dir });
    spawnSync("git", ["config", "user.email", "t@test.local"], { cwd: dir });
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.mkdirSync(path.join(dir, "bin"), { recursive: true });
    fs.symlinkSync(binPath, path.join(dir, "bin", "vstack.mjs"));
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "export const a = 1;\n");

    const installed = manageHooks(dir, "on", { harnesses: ["claude", "codex", "cursor"], commandPrefix: "node bin/vstack.mjs" });
    assert.equal(installed.enabled, true);

    const claudeCfg = JSON.parse(fs.readFileSync(path.join(dir, ".claude", "settings.local.json"), "utf8")) as {
      hooks: { PreToolUse: Array<{ matcher: string; hooks: Array<{ type: string; command: string; timeout: number }> }> };
    };
    const cmd = claudeCfg.hooks.PreToolUse[0]?.hooks[0]?.command ?? "";
    const shMatch = /^sh\s+-c\s+'(.+)'$/.exec(cmd);
    assert.ok(shMatch?.[1], `Expected root-anchored sh -c hook command, got: ${cmd}`);
    const fromSubdir = spawnSync("sh", ["-c", shMatch[1]], {
      cwd: path.join(dir, "src"),
      input: JSON.stringify({ cwd: path.join(dir, "src"), tool_name: "Write", tool_input: { file_path: path.join(dir, "src", "slop.ts"), content: "export const s = (1 as any);\n" } }),
      encoding: "utf8",
    });
    assert.equal(fromSubdir.status, 2);

    const cursorPath = path.join(dir, ".cursor", "hooks.json");
    const cursorOrig = fs.readFileSync(cursorPath, "utf8");
    fs.writeFileSync(cursorPath, cursorOrig.replace('"failClosed": true', '"failClosed": false'));
    assert.equal(runDoctor(dir).healthy, false);
    fs.writeFileSync(cursorPath, cursorOrig.replace("Write|Edit|StrReplace|Delete", "Write|Edit"));
    assert.equal(runDoctor(dir).healthy, false);
    fs.writeFileSync(cursorPath, cursorOrig);

    const claudePath = path.join(dir, ".claude", "settings.local.json");
    const claudeOrig = fs.readFileSync(claudePath, "utf8");
    fs.writeFileSync(claudePath, claudeOrig.replace('"timeout": 15', '"timeout": 0.001'));
    assert.equal(runDoctor(dir).healthy, false);
    fs.writeFileSync(claudePath, claudeOrig.replace('"type": "command"', '"type": "prompt"'));
    assert.equal(runDoctor(dir).healthy, false);
    fs.writeFileSync(claudePath, JSON.stringify({ ...JSON.parse(claudeOrig), env: { VSTACK_HOOK_DISABLED: "1" } }));
    assert.equal(runDoctor(dir).healthy, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
