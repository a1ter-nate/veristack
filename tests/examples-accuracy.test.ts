import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { scanRepo } from "../src/ladder.ts";

interface ExampleManifest {
  language: string;
  caught: Record<string, string[]>;
  clean: string[];
}

const examplesRoot = path.resolve(import.meta.dir, "..", "examples");
const languages = ["typescript", "csharp", "rust", "python"] as const;

for (const lang of languages) {
  test(`examples/${lang}: caught/ hits exact expected rules and clean/ produces zero false positives`, () => {
    const langDir = path.join(examplesRoot, lang);
    const manifest = JSON.parse(fs.readFileSync(path.join(langDir, "manifest.json"), "utf8")) as ExampleManifest;
    assert.equal(manifest.language, lang);

    const caughtReport = scanRepo(path.join(langDir, "caught"));
    for (const [relFile, expectedRules] of Object.entries(manifest.caught)) {
      const actualRules = [...new Set(caughtReport.findings.filter((f) => f.file === relFile).map((f) => f.rule))].sort();
      const sortedExpected = [...expectedRules].sort();
      assert.deepEqual(
        actualRules,
        sortedExpected,
        `examples/${lang}/caught/${relFile}: expected [${sortedExpected.join(", ")}] but got [${actualRules.join(", ")}]`,
      );
    }

    const cleanReport = scanRepo(path.join(langDir, "clean"));
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
