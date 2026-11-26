import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { auditCiWorkflows } from "../src/ci-auditor.ts";
import type { DiscoveredRepo } from "../src/discover.ts";
import { analyzeTests } from "../src/test-analyzer.ts";

interface TestCaseRow {
  name: string;
  file: string;
  content: string;
  expectedRules: string[];
  expectedPushDowns: string[];
}

interface CiCaseRow {
  name: string;
  file: string;
  content: string;
  expectedRules: string[];
}

interface FixtureFile {
  testCases: TestCaseRow[];
  ciCases: CiCaseRow[];
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(here, "fixtures", "detector-cases.json");
const fixture: FixtureFile = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

function fakeRepo(file: string, content: string, isTest: boolean, isWorkflow: boolean): DiscoveredRepo {
  return {
    root: "/virtual",
    allRelPaths: [file],
    languages: ["typescript"],
    archetype: "fullstack",
    observedArchetype: "fullstack",
    scopeExclusions: [],
    ci: {
      hasCiWorkflows: false,
      workflowFiles: [],
      runsFormatterOrLint: false,
      runsTypeOrStructureCheck: false,
      runsUnitTests: false,
      runsBoundaryOrMbtTests: false,
      runsIntegrationOrDbTests: false,
      runsMutationOrFormal: false,
      runsPerfOrBench: false,
      runsE2eTests: false,
      runsProdVerification: false,
    },
    files: [
      {
        rel: file,
        abs: `/virtual/${file}`,
        language: isWorkflow ? undefined : "typescript",
        isTest,
        isWorkflow,
        content,
        lines: content.split(/\r?\n/).length,
      },
    ],
    signals: {
      hasFormatter: false,
      hasLinter: false,
      hasOxlint: false,
      hasAntiSlop: false,
      hasLandmines: false,
      hasGoInternal: false,
      hasDeslopPlease: false,
      hasDesloppify: false,
      hasStrictTypes: false,
      hasTsgo: false,
      hasKnipOrDeadCode: false,
      hasJscpd: false,
      hasArchFitness: false,
      hasPreCommitHook: false,
      hasCodeowners: false,
      hasReviewMd: false,
      hasAgentsMd: false,
      hasPbt: false,
      hasMbt: false,
      hasContractTool: false,
      hasComponentUiTool: false,
      hasMsw: false,
      hasMswStrict: false,
      hasTestcontainersOrRealDb: false,
      hasMigrationTest: false,
      hasBusDlqTest: false,
      hasDst: false,
      hasDryRun: false,
      hasMutationTool: false,
      hasFormalTool: false,
      hasFuzzTool: false,
      hasBombadil: false,
      hasVisualTool: false,
      hasPerfOrLoadTool: false,
      hasE2eTool: false,
      hasProdTelemetryOrCanary: false,
      hasDiffSelection: false,
    },
  };
}

for (const row of fixture.testCases) {
  test(`test-analyzer: ${row.name}`, () => {
    const result = analyzeTests(fakeRepo(row.file, row.content, true, false));
    const observedRules = [...new Set(result.findings.map((f) => f.rule))].sort();
    const observedPushDowns = [...new Set(result.pushDownOpportunities.map((p) => p.pattern))].sort();
    assert.deepEqual(observedRules, [...row.expectedRules].sort());
    assert.deepEqual(observedPushDowns, [...row.expectedPushDowns].sort());
  });
}

for (const row of fixture.ciCases) {
  test(`ci-auditor: ${row.name}`, () => {
    const findings = auditCiWorkflows(fakeRepo(row.file, row.content, false, true));
    const observedRules = [...new Set(findings.map((f) => f.rule))].sort();
    assert.deepEqual(observedRules, [...row.expectedRules].sort());
  });
}
