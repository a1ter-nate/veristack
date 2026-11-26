import assert from "node:assert/strict";
import test from "node:test";
import fc from "fast-check";
import { lintNoComments } from "../../src/no-comments.ts";
import { buildRatchetBaseline, evaluateRatchet, type RatchetBaseline } from "../../src/ratchet.ts";
import { computeCrapScore, reportParsers } from "../../src/rungs/reports.ts";
const { parseCoberturaXml, parseJunitOrTrx, parseLcov, parseStrykerJson } = reportParsers;
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import type { Finding, RungStatus } from "../../src/types.ts";

function makeFinding(rule: string, idx: number, severity: Finding["severity"] = "error"): Finding {
  return {
    id: `F:${rule}:${idx}`,
    rule,
    category: "cheat",
    rung: "R0",
    severity,
    file: "src/a.ts",
    line: idx + 1,
    message: "m",
    fix: "f",
  };
}

function makeRung(
  rung: RungStatus["rung"],
  grade: RungStatus["coverageGrade"],
  score: number,
  executedInCi: boolean,
): RungStatus {
  return {
    rung,
    name: rung,
    speedBudget: "< 2s",
    targetBudget: "100%",
    status: grade === "well-covered" ? "covered" : grade === "poorly-covered" ? "partial" : grade === "not-applicable" ? "not-applicable" : "hole",
    coverageGrade: grade,
    coverageScore: score,
    executedInCi,
    receiptVerified: executedInCi,
    idealCoverage: "ideal",
    observedCoverage: "actual",
    checks: [],
    observedCount: 1,
    evidence: grade === "not-covered" ? [] : ["ev"],
    gaps: [],
  };
}

interface RatchetModel {
  counts: Record<string, number>;
  r0Grade: RungStatus["coverageGrade"];
  r2Grade: RungStatus["coverageGrade"];
}

interface RatchetSut {
  baseline: RatchetBaseline;
  rungs: RungStatus[];
}

function buildFindings(counts: Record<string, number>): Finding[] {
  return Object.entries(counts).flatMap(([rule, count]) =>
    Array.from({ length: count }, (_, idx) => makeFinding(rule, idx)),
  );
}

class RegressRuleCommand implements fc.Command<RatchetModel, RatchetSut> {
  readonly rule: string;
  constructor(rule: string) {
    this.rule = rule;
  }
  check(): boolean {
    return true;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    const nextCounts = { ...m.counts, [this.rule]: (m.counts[this.rule] ?? 0) + 1 };
    const evalRes = evaluateRatchet(buildFindings(nextCounts), s.baseline, s.rungs);
    assert.equal(evalRes.passed, false);
    assert.ok(evalRes.regressions.some((r) => r.rule === this.rule));
  }
  toString(): string {
    return `Regress(${this.rule})`;
  }
}

class TightenRuleCommand implements fc.Command<RatchetModel, RatchetSut> {
  readonly rule: string;
  constructor(rule: string) {
    this.rule = rule;
  }
  check(m: Readonly<RatchetModel>): boolean {
    return (m.counts[this.rule] ?? 0) > 0;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    m.counts[this.rule] = (m.counts[this.rule] ?? 1) - 1;
    const findings = buildFindings(m.counts);
    const beforeTighten = evaluateRatchet(findings, s.baseline, s.rungs);
    assert.equal(beforeTighten.passed, false);
    assert.ok(beforeTighten.tightenAvailable.some((t) => t.rule === this.rule));
    s.baseline = buildRatchetBaseline(findings, s.rungs);
    const afterTighten = evaluateRatchet(findings, s.baseline, s.rungs);
    assert.equal(afterTighten.passed, true);
  }
  toString(): string {
    return `Tighten(${this.rule})`;
  }
}

class ArchetypeDowngradeCommand implements fc.Command<RatchetModel, RatchetSut> {
  check(): boolean {
    return true;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    const degraded = s.rungs.map((r) => (r.rung === "R0" ? makeRung("R0", "not-applicable", 100, false) : r));
    const res = evaluateRatchet(buildFindings(m.counts), s.baseline, degraded);
    assert.equal(res.passed, false);
    assert.ok(res.rungRegressions.some((rr) => rr.rung === "R0"));
  }
  toString(): string {
    return "ArchetypeDowngrade(R0)";
  }
}

test("fast-check PBT: lintNoComments produces 0 FPs on generated strings and catches every generated comment", () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 10000 }), fc.integer({ min: 0, max: 10000 }), (a, b) => {
      const clean = `export const v = "https://example.com/${a}" + String(${a} + ${b});\n`;
      assert.deepEqual(lintNoComments("src/gen.ts", clean, "typescript"), []);

      const dirty = `// generated prose ${a}\n${clean}`;
      const hits = lintNoComments("src/gen.ts", dirty, "typescript");
      assert.equal(hits.length, 1);
      assert.equal(hits[0]?.rule, "no-comments");
    }),
    { seed: 20261125, numRuns: 50 },
  );
});

test("fast-check PBT: CRAP score is monotonic in complexity and decreases with coverage", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 30 }),
      fc.double({ min: 0, max: 1, noNaN: true }),
      (cc, cov) => {
        const score = computeCrapScore(cc, cov);
        assert.ok(score >= cc);
        assert.ok(computeCrapScore(cc, 1) === cc);
        assert.ok(computeCrapScore(cc, 0) === cc * cc + cc);
      },
    ),
    { seed: 7777, numRuns: 60 },
  );
});

test("fast-check stateful MBT: ratchet monotonicity and archetype-downgrade rejection hold under fc.commands", () => {
  const cmds = [
    fc.constantFrom("rA", "rB", "rC").map((r) => new RegressRuleCommand(r)),
    fc.constantFrom("rA", "rB", "rC").map((r) => new TightenRuleCommand(r)),
    fc.constant(new ArchetypeDowngradeCommand()),
  ];
  fc.assert(
    fc.property(fc.commands(cmds, { maxCommands: 20 }), (seq) => {
      const initCounts = { rA: 3, rB: 2, rC: 2 };
      const initRungs = [makeRung("R0", "well-covered", 100, true), makeRung("R2", "poorly-covered", 60, true)];
      const model: RatchetModel = { counts: { ...initCounts }, r0Grade: "well-covered", r2Grade: "poorly-covered" };
      const sut: RatchetSut = {
        baseline: buildRatchetBaseline(buildFindings(initCounts), initRungs),
        rungs: initRungs,
      };
      fc.modelRun(() => ({ model, real: sut }), seq);
    }),
    { seed: 424242, numRuns: 40 },
  );
});

test("parseGitHubWorkflow preserves quoted # tokens and strips column-0 and inline YAML comments", () => {
  const wf = [
    "# column-0 comment",
    "name: Real CI",
    "on: [pull_request]",
    "jobs:",
    "  verify:",
    "    steps:",
    '      - run: bun test --grep "case#1 \\"quoted\\"" # inline comment',
    "      - run: oxlint . # trailing oxlint comment",
  ].join("\n");
  const parsed = parseGitHubWorkflow({
    rel: ".github/workflows/real.yml",
    abs: "/virtual/.github/workflows/real.yml",
    isTest: false,
    isWorkflow: true,
    content: wf,
    lines: 8,
  });
  assert.equal(parsed.isPrBlocking, true);
  assert.deepEqual(parsed.activeCommands, ['bun test --grep "case#1 \\"quoted\\""', "oxlint ."]);
});

test("structured report adapters parse LCOV, Cobertura, Stryker JSON, JUnit XML, and .NET TRX accurately", () => {
  const lcov = parseLcov("SF:src/a.ts\nDA:1,1\nDA:2,0\nend_of_record\n");
  assert.equal(lcov.get("src/a.ts"), 0.5);

  const cob = parseCoberturaXml('<coverage><class filename="src/b.cs" line-rate="0.75" /></coverage>');
  assert.equal(cob.get("src/b.cs"), 0.75);

  const stryker = parseStrykerJson(
    JSON.stringify({
      files: {
        "src/a.ts": {
          mutants: [
            { status: "Killed" },
            { status: "Timeout" },
            { status: "Survived" },
            { status: "CompileError" },
            { status: "Ignored" },
          ],
        },
      },
    }),
  );
  assert.equal(stryker, 66.67);

  const junit = parseJunitOrTrx('<testsuite tests="10" failures="1" errors="0" skipped="2"></testsuite>');
  assert.deepEqual(junit, { passed: 7, failed: 1, skipped: 2 });

  const trx = parseJunitOrTrx('<ResultSummary><Counters total="12" passed="11" failed="1" /></ResultSummary>');
  assert.deepEqual(trx, { passed: 11, failed: 1, skipped: 0 });
});
