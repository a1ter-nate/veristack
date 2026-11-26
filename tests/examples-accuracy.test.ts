import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../src/ladder.ts";

interface ExampleManifest {
  language: string;
  caught: Record<string, string[]>;
  clean: string[];
}

const repoRoot = path.resolve(import.meta.dir, "..");
const examplesRoot = path.join(repoRoot, "examples");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const languages = ["typescript", "csharp", "rust", "python"] as const;

function listFiles(dir: string): string[] {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && !entry.name.startsWith("."))
    .map((entry) => entry.name)
    .sort();
}

for (const lang of languages) {
  test(`examples/${lang}: every caught/ & clean/ file is manifest-tracked with exact TP rules and zero FPs`, () => {
    const langDir = path.join(examplesRoot, lang);
    const caughtDir = path.join(langDir, "caught");
    const cleanDir = path.join(langDir, "clean");
    const manifest = JSON.parse(fs.readFileSync(path.join(langDir, "manifest.json"), "utf8")) as ExampleManifest;
    assert.equal(manifest.language, lang);

    assert.deepEqual(
      Object.keys(manifest.caught).sort(),
      listFiles(caughtDir),
      `examples/${lang}/manifest.json caught keys must match every file in caught/`,
    );
    assert.deepEqual(
      [...manifest.clean].sort(),
      listFiles(cleanDir),
      `examples/${lang}/manifest.json clean entries must match every file in clean/`,
    );

    const caughtReport = scanRepo(caughtDir);
    for (const [relFile, expectedRules] of Object.entries(manifest.caught)) {
      const actualRules = [...new Set(caughtReport.findings.filter((f) => f.file === relFile).map((f) => f.rule))].sort();
      const sortedExpected = [...expectedRules].sort();
      assert.deepEqual(
        actualRules,
        sortedExpected,
        `examples/${lang}/caught/${relFile}: expected [${sortedExpected.join(", ")}] but got [${actualRules.join(", ")}]`,
      );
    }

    const cleanReport = scanRepo(cleanDir);
    for (const relFile of manifest.clean) {
      const fileFindings = cleanReport.findings.filter((f) => f.file === relFile);
      assert.deepEqual(
        fileFindings.map((f) => `${f.rule}@${f.line}`),
        [],
        `examples/${lang}/clean/${relFile}: expected 0 false positives but got ${fileFindings.map((f) => `${f.rule}@${f.line}: ${f.message}`).join("; ")}`,
      );
    }
  });
}

test("vstack CLI exits 1 on examples/*/caught and exits 0 on examples/*/clean", () => {
  for (const lang of languages) {
    const caughtDir = path.join(examplesRoot, lang, "caught");
    const cleanDir = path.join(examplesRoot, lang, "clean");

    const caughtScan = spawnSync(process.execPath, [cliPath, "scan", caughtDir, "--fail-on-errors"], {
      encoding: "utf8",
    });
    assert.equal(caughtScan.status, 1, `vstack scan --fail-on-errors must fail on examples/${lang}/caught`);

    const cleanScan = spawnSync(
      process.execPath,
      [cliPath, "scan", cleanDir, "--fail-on-errors", "--allow-missing-rungs"],
      { encoding: "utf8" },
    );
    assert.equal(cleanScan.status, 0, `vstack scan --fail-on-errors must pass on examples/${lang}/clean`);

    const cleanSm = spawnSync(process.execPath, [cliPath, "state-machines", cleanDir, "--fail"], {
      encoding: "utf8",
    });
    assert.equal(cleanSm.status, 0, `vstack state-machines --fail must pass on examples/${lang}/clean`);

    const cleanComments = spawnSync(process.execPath, [cliPath, "no-comments", cleanDir, "--fail"], {
      encoding: "utf8",
    });
    assert.equal(cleanComments.status, 0, `vstack no-comments --fail must pass on examples/${lang}/clean`);
  }
});
