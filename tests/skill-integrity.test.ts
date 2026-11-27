import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { discoverRepo } from "@veristack/core";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const skillRoot = path.join(repoRoot, "skill");

function parseFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  assert.ok(match, "SKILL.md must start with a YAML frontmatter block");
  const fields: Record<string, string> = {};
  for (const rawLine of (match[1] ?? "").split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    const sep = trimmed.indexOf(":");
    assert.ok(sep > 0, `Invalid frontmatter line: ${trimmed}`);
    const key = trimmed.slice(0, sep).trim();
    const rawVal = trimmed.slice(sep + 1).trim();
    if (rawVal.includes(": ")) {
      assert.ok(
        (rawVal.startsWith('"') && rawVal.endsWith('"')) || (rawVal.startsWith("'") && rawVal.endsWith("'")),
        `Frontmatter value containing ": " must be quoted for key "${key}"`,
      );
    }
    fields[key] = rawVal.replace(/^["']|["']$/g, "");
  }
  return fields;
}

test("shipped Veristack SKILL.md has strict frontmatter and synced agents/openai.yaml", () => {
  const skillMdPath = path.join(skillRoot, "SKILL.md");
  const openaiYamlPath = path.join(skillRoot, "agents", "openai.yaml");
  assert.equal(fs.existsSync(skillMdPath), true);
  assert.equal(fs.existsSync(openaiYamlPath), true);

  const frontmatter = parseFrontmatter(fs.readFileSync(skillMdPath, "utf8"));
  assert.equal(frontmatter.name, "veristack");
  assert.ok((frontmatter.description ?? "").length > 20);
  assert.ok((frontmatter.description ?? "").length <= 320);

  const openaiYaml = fs.readFileSync(openaiYamlPath, "utf8");
  assert.match(openaiYaml, /display_name:\s*"Veristack"/);
  assert.match(openaiYaml, /short_description:\s*".+"/);
  const isUserOnly = frontmatter["disable-model-invocation"] === "true";
  const hasDisablePolicy = /allow_implicit_invocation:\s*false/.test(openaiYaml);
  assert.equal(isUserOnly, hasDisablePolicy);
});

function collectMarkdownFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectMarkdownFiles(full));
    else if (entry.name.endsWith(".md")) out.push(full);
  }
  return out;
}

test("all relative markdown pointers under skill/ resolve to existing files and stay clean", () => {
  const repo = discoverRepo(repoRoot);
  assert.ok(repo.allRelPaths.includes("skill/SKILL.md"));

  const skillMarkdownFiles = collectMarkdownFiles(skillRoot);
  assert.equal(skillMarkdownFiles.length, 13);

  const linkRegex = /\[[^\]]+\]\(([^)]+)\)/g;
  for (const abs of skillMarkdownFiles) {
    const rel = path.relative(repoRoot, abs);
    const content = fs.readFileSync(abs, "utf8");
    assert.equal(/verification-stack\/SKILL\.md/.test(content), false, `Stale skill pointer in ${rel}`);
    for (const match of content.matchAll(linkRegex)) {
      const target = (match[1] ?? "").split("#")[0]?.trim() ?? "";
      if (!target || /^(?:https?:|mailto:)/i.test(target)) continue;
      const resolved = path.resolve(path.dirname(abs), target);
      assert.equal(fs.existsSync(resolved), true, `Broken relative pointer "${target}" in ${rel}`);
    }
  }
});
