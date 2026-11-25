import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "./discover.ts";
import { hasNonFrameworkImport, lineOf, maskStrings, scanVitestConfigs } from "./test-lexical.ts";
import type { Finding, PushDownOpportunity, RungId, TestBoundary, TestFileRecord } from "./types.ts";

export interface TestAnalysisResult {
  inventory: TestFileRecord[];
  findings: Finding[];
  pushDownOpportunities: PushDownOpportunity[];
}

const TEST_CASE_DECL =
  /\b(?:test|it)(?:\.(?:only|skip|concurrent|each))?\s*\(|\[(?:Fact|Theory|Test|TestCase|TestMethod|Property)\b|\bdef\s+test_[a-zA-Z0-9_]+\s*\(|\bfunc\s+Test[A-Z][a-zA-Z0-9_]*\s*\(|#\[(?:test|tokio::test|rstest)\]/g;
const TABLE_TEST =
  /\b(?:test|it)\.each\s*\(|\[Theory\]|\[InlineData\(|\[MemberData\(|#\[rstest\]|#\[case\(|@pytest\.mark\.parametrize\b|\.csv["']|\.ya?ml["']|fixtures\/.*\.json/i;
const PBT_SIGNAL = /\b(?:fc\.property|fc\.asyncProperty|fast-check|@given\(|hypothesis|proptest!|\[Property(?:\(|\])|FsCheck)\b/i;
const MBT_SIGNAL =
  /\b(?:fc\.commands|fc\.modelRun|fc\.asyncModelRun|RuleBasedStateMachine|PropEr|stateright|FsCheck\.Experimental|StateMachine<|Machine<|proptest_state_machine|ReferenceStateMachine|state_machine_test!)\b/i;
const E2E_SIGNAL = /\b(?:@playwright\/test|page\.goto\(|cy\.visit\(|webdriver|selenium|puppeteer)\b/i;
const COMPONENT_SIGNAL = /\b(?:@testing-library|render\(|screen\.getBy|mount\(|playwright\/experimental-ct)\b/i;
const HOST_SIGNAL = /\b(?:WebApplicationFactory|TestServer|supertest\(|app\.request\(|TestClient\(|oneshot\(|actix_web::test)\b/i;
const CONTRACT_SIGNAL = /\b(?:@pact-foundation|PactBuilder|VerifyProvider|schemathesis|OpenApiValidator|openapi-response-contract)\b/i;
const REAL_DB_SIGNAL =
  /\b(?:Testcontainers|PostgreSqlContainer|MsSqlContainer|UseNpgsql|UseSqlServer|SqlConnection|pg\.Pool|PgPool::connect|sqlx::test|PGlite|MigrateAsync|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|firebase-emulator|initializeTestEnvironment)\b/i;
const REAL_BUS_SIGNAL = /\b(?:ServiceBusClient|RabbitMQ|KafkaContainer|DeadLetter|MaxDeliveryCount)\b/i;
const NETWORK_MOCK_SIGNAL = /\b(?:page\.route|cy\.intercept|setupServer|nock|wiremock::MockServer|mockito::Server|respx\.mock)\s*\(|\b(?:msw|respx)\b/i;

const MODULE_MOCK = /\b(?:vi|jest)\.mock\s*\(|\b(?:vi|jest)\.unstable_mockModule\s*\(|\bmock\.module\s*\(|\b(?:unittest\.mock\.)?patch(?:\.object)?\s*\(/g;
const TEST_DOUBLE =
  /\bnew\s+Mock\s*<|\bSubstitute\.For\s*[<(]|\bA\.Fake\s*<|\bMock[A-Z][A-Za-z0-9_]*::new\s*\(|#\[automock\]|\b(?:MagicMock|AsyncMock|Mock)\s*\(|\bsinon\.(?:stub|mock)\s*\(|\bvi\.fn\s*\(\s*(?:\(|async|function)/g;
const FIXED_SLEEP =
  /\b(?:page|Page)\.waitForTimeout(?:Async)?\s*\(|\bcy\.wait\(\s*\d+|\bThread\.Sleep\s*\(|\bTask\.Delay\(\s*\d+|\b(?:std::)?thread::sleep\s*\(|\btokio::time::sleep\s*\(|\b(?:time|asyncio)\.sleep\s*\(|\bnew\s+Promise\s*\([^)]*setTimeout|\bnetworkidle\b/g;
const FLAKE_MASK_ANYWHERE = /\bjest\.retryTimes\s*\(|\bpytest\.mark\.flaky\b|--reruns\b|\bconfigure\s*\(\s*\{[^}]*\bretries\s*:\s*[1-9]/g;
const FLAKE_MASK_CONFIG = /\bretries\s*:\s*[1-9]/g;
const SKIP_OR_ONLY =
  /\b(?:describe|test|it)(?:\.concurrent)?\.(?:only|todo|fixme)\s*\(|\b(?:fdescribe|fit|xdescribe|xit|xtest)\s*\(|\[(?:Fact|Theory|Test|TestMethod)\s*\([^\]]*\bSkip\s*=|\[Ignore\b|#\[ignore\b|@pytest\.mark\.(?:skip|xfail)\b|@unittest\.skip\b/g;
const UNCONDITIONAL_SKIP = /\b(?:describe|test|it)(?:\.concurrent)?\.skip\s*\(\s*(?:["'`])/g;
const TAUTOLOGY =
  /\bexpect\(\s*(?:true|false)\s*\)|\bassert\.ok\(\s*true\s*\)|\bAssert\.(?:True|IsTrue)\(\s*true\s*\)|\bAssert\.Pass\s*\(|\bassert!\(\s*true\s*\)|\bassert_eq!\(\s*(\d+|true|false)\s*,\s*\1\s*\)|^\s*assert\s+(?:True|1\s*==\s*1)\b/gm;
const EXISTENCE_ONLY = /\.toBe(?:Truthy|Defined)\s*\(\s*\)|\bAssert\.(?:NotNull|IsNotNull)\s*\(/g;
const CONDITIONAL_EXPECT = /\bif\s*\([^)]+\)\s*\{?[^{};]{0,120}\b(?:expect|assert|Assert|assert!|assert_eq!|assert_ne!)\s*\(/g;
const WALL_CLOCK =
  /\bexpect\s*\(\s*(?:Date\.now\(\)|performance\.now\(\))\s*-\s*[a-zA-Z0-9_]+\s*\)\s*\.toBeLessThan|\.Elapsed(?:Milliseconds|Ticks|TotalMilliseconds)\s*<|\.elapsed\s*\(\s*\)(?:\.as_(?:millis|secs|micros)\s*\(\s*\))?\s*<|\b(?:time\.(?:monotonic|perf_counter|time)\s*\(\s*\))\s*-\s*[a-zA-Z0-9_]+\s*</g;
const IMPORTED_MUTATION =
  /\bprocess\.env\.[A-Z0-9_]+\s*=|\bObject\.assign\s*\(\s*(?:process\.env|env)\b|\bEnvironment\.SetEnvironmentVariable\s*\(|\b(?:std::)?env::set_var\s*\(|\bos\.environ\s*\[[^\]]+\]\s*=|\bos\.putenv\s*\(/g;
const TAILWIND_ASSERT = /\.toHaveClass\s*\(\s*["'][^"']*(?:bg-|text-|flex|hidden|opacity-|p-\d|m-\d)/g;
const XPATH_OR_CSS = /\bBy\.XPath\s*\(|\blocator\(\s*['"]\/\/|\blocator\(\s*['"][^'"]*(?:>|>>)[^'"]*(?:>|>>)/g;
const SAME_CALL_EXPECT =
  /\bexpect\(\s*([A-Za-z_$][A-Za-z0-9_$.]*\([^()\n]{1,60}\))\s*\)\s*\.(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)|\bAssert\.(?:Equal|StrictEqual|AreEqual)\(\s*([A-Za-z_][A-Za-z0-9_.]*\([^()\n]{1,60}\))\s*,\s*\2\s*\)|\bassert_eq!\(\s*([A-Za-z_][A-Za-z0-9_.:]*\([^()\n]{1,60}\))\s*,\s*\3\s*\)|\bassert\s+([A-Za-z_][A-Za-z0-9_.]*\([^()\n]{1,60}\))\s*==\s*\4(?=\s|$|#)/gm;
const PARAM_BRANCH = /\b(?:test|it)\.each\s*\([\s\S]{0,600}?\b(?:if|switch)\s*\(|\[InlineData\([\s\S]{0,400}?\bswitch\s*\(/g;
const MULTI_STATUS_ASSERT =
  /\bexpect\s*\(\s*\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}[^\]]*\]\s*\)\s*\.(?:toContain|toContainEqual)\s*\(|\.\s*toBeOneOf\s*\(\s*\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}[^\]]*\]\s*\)|\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}[^\]]*\]\s*\.(?:includes|contains)\s*\(|\bAssert\.Contains\s*\([^;\n]*HttpStatusCode\.\w+[^;\n]*HttpStatusCode\.\w+|\bstatus_code\s+in\s*(?:\(|\[|\{)\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}/g;
const FETCH_STUB =
  /\bvi\.stubGlobal\s*\(\s*["']fetch["']|\bvi\.spyOn\s*\(\s*(?:globalThis|window|global|self)\s*,\s*["']fetch["']|\b(?:globalThis|window|global|self)\.fetch\s*=/g;
const TEST_NONDETERMINISM =
  /\bMath\.random\s*\(|\bDate\.now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)|\bDateTime(?:Offset)?\.(?:Now|UtcNow)\b|\bnew\s+Random\s*\(\s*\)|\bRandom\.Shared\b|\bSystemTime::now\s*\(|\b(?:Utc|Local)::now\s*\(|\brand::(?:random|thread_rng|rng)\s*\(|\bdatetime\.(?:utc)?now\s*\(|\brandom\.(?:random|randint|choice)\s*\(|\btime\.time\s*\(\s*\)/g;
const COVERAGE_FARM_NAME = /(?:^|[-_.])(?:coverage-|closeout|easy-?wins|zero-?coverage|leftovers)/i;
const COVERAGE_POLICY_TOOLING =
  /\bcoverage-(?:policy|floor|floors|inventory|gate|gates|config|check|checks|report|summary|threshold|thresholds|ratchet|baseline)\b/i;

function classifyBoundary(file: ScannedFile, code: string, repoHasEmulator: boolean): { boundary: TestBoundary; rung: RungId } {
  if (E2E_SIGNAL.test(code) || /\.e2e\.|\/e2e\//i.test(file.rel)) return { boundary: "e2e", rung: "R7" };
  if (REAL_DB_SIGNAL.test(code) || REAL_BUS_SIGNAL.test(code)) return { boundary: "integration", rung: "R4" };
  if (repoHasEmulator && /(?:cloud-integration|emulator)/i.test(file.rel)) return { boundary: "integration", rung: "R4" };
  if (MBT_SIGNAL.test(code)) return { boundary: "mbt", rung: "R3" };
  if (CONTRACT_SIGNAL.test(code)) return { boundary: "contract", rung: "R3" };
  if (HOST_SIGNAL.test(code)) return { boundary: "host", rung: "R3" };
  if (COMPONENT_SIGNAL.test(code)) return { boundary: "component", rung: "R3" };
  return { boundary: "unit", rung: "R2" };
}

function scanSingleTestFile(file: ScannedFile, repoHasEmulator: boolean): {
  record: TestFileRecord;
  findings: Finding[];
  pushDowns: PushDownOpportunity[];
} {
  const raw = file.content;
  const code = maskStrings(raw);
  const findings: Finding[] = [];
  const pushDowns: PushDownOpportunity[] = [];
  const { boundary, rung } = classifyBoundary(file, code, repoHasEmulator);

  const testCases = code.match(TEST_CASE_DECL)?.length ?? 0;
  const hasTable = TABLE_TEST.test(raw);
  const hasPbt = PBT_SIGNAL.test(raw);
  const hasMbt = MBT_SIGNAL.test(code);
  const hasRealDb = REAL_DB_SIGNAL.test(code) || (repoHasEmulator && /(?:cloud-integration|emulator)/i.test(file.rel));
  const hasRealBus = REAL_BUS_SIGNAL.test(code);
  const hasNetworkMock = NETWORK_MOCK_SIGNAL.test(code);
  const isConfigFile = /(?:config|playwright|vitest|jest)\.[cm]?[jt]s$/i.test(file.rel);

  const addMatches = (
    target: string,
    regex: RegExp,
    rule: string,
    category: Finding["category"],
    severity: Finding["severity"],
    message: string,
    fix: string,
    limit = 5,
  ): number => {
    let count = 0;
    for (const m of target.matchAll(regex)) {
      count += 1;
      if (count <= limit) {
        const line = lineOf(target, m.index ?? 0);
        findings.push({
          id: `TS:${rule}:${file.rel}:${line}`,
          rule,
          category,
          rung: "R0",
          severity,
          file: file.rel,
          line,
          message,
          fix,
        });
      }
    }
    return count;
  };

  const baseName = path.posix.basename(file.rel);
  if (COVERAGE_FARM_NAME.test(baseName) && !COVERAGE_POLICY_TOOLING.test(baseName)) {
    findings.push({
      id: `TS:coverage-farm:${file.rel}:1`,
      rule: "no-coverage-farm-file",
      category: "test-smell",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line: 1,
      message: `Test file ${file.rel} is named for coverage farming rather than observable behavior.`,
      fix: "Move genuinely behavioral cases next to the unit under test and delete coverage-padding leftovers.",
    });
  }

  if (
    (file.language === "typescript" ||
      file.language === "javascript" ||
      file.language === "csharp" ||
      file.language === "rust" ||
      file.language === "python") &&
    testCases > 0 &&
    boundary === "unit" &&
    !hasNonFrameworkImport(raw, file.language) &&
    !/\b(?:spawnSync|execFileSync|execSync|Command::new)\s*\(/.test(code) &&
    !(
      (file.language === "typescript" || file.language === "javascript") &&
      /\b(?:function|const|class)\s+[A-Za-z0-9_]+/.test(code)
    )
  ) {
    findings.push({
      id: `TS:unexercised:${file.rel}:1`,
      rule: "no-unexercised-test",
      category: "test-smell",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line: 1,
      message: "Test file defines test cases without importing any symbol from production code.",
      fix: "Import and exercise the real unit under test with an independent oracle, or delete the dead test.",
    });
  }

  addMatches(
    code,
    MODULE_MOCK,
    "no-test-doubles",
    "test-smell",
    "error",
    "Module mock replaces real dependency behavior.",
    "Use the real implementation, a DI port, or strict MSW at the network boundary.",
  );

  addMatches(
    raw,
    FETCH_STUB,
    "no-fetch-stub",
    "test-smell",
    "error",
    "Replacing global fetch hides unhandled network calls.",
    "Serve HTTP through a shared strict MSW server (onUnhandledRequest: 'error') instead of stubbing fetch.",
  );

  const doubleCount = code.match(TEST_DOUBLE)?.length ?? 0;
  if (doubleCount >= 3) {
    findings.push({
      id: `TS:overheavy-mocks:${file.rel}:1`,
      rule: "overheavy-mocks",
      category: "test-smell",
      rung: "R0",
      severity: "error",
      file: file.rel,
      line: 1,
      message: `${doubleCount} test doubles in one file — tests the mock graph instead of real behavior.`,
      fix: "Deepen the module and test at the outer public seam with real collaborators or boundary adapters.",
    });
  }

  addMatches(
    code,
    FIXED_SLEEP,
    "no-fixed-sleep",
    "cheat",
    "error",
    "Fixed sleep or networkidle wait introduces flakiness and slows CI.",
    "Await an explicit completion event, emitted signal, or web-first locator assertion.",
  );

  addMatches(
    code,
    isConfigFile ? FLAKE_MASK_CONFIG : FLAKE_MASK_ANYWHERE,
    "no-flake-masking",
    "cheat",
    "error",
    "Retry config masks flaky tests instead of fixing root causes.",
    "Remove retries, diagnose the non-determinism, or delete the unfixable test with a note.",
  );

  addMatches(
    code,
    SKIP_OR_ONLY,
    "test-discipline",
    "cheat",
    "error",
    "Focused (.only) or disabled (.todo/.fixme/Ignore) test committed.",
    "Restore a deterministic assertion or remove dead tests; never silently skip gating checks.",
  );

  addMatches(
    raw,
    UNCONDITIONAL_SKIP,
    "test-discipline",
    "cheat",
    "error",
    "Unconditionally skipped test (.skip) committed.",
    "Fix, delete, or track in a known-defect ledger; a skipped test proves nothing.",
  );

  addMatches(
    code,
    MULTI_STATUS_ASSERT,
    "no-multi-status-assertion",
    "test-smell",
    "error",
    "Assertion accepts multiple HTTP statuses and passes whether the call succeeded or failed.",
    "Assert the single exact HTTP status promised by the contract.",
  );

  addMatches(
    code,
    TAUTOLOGY,
    "weak-asserts-tautology",
    "test-smell",
    "error",
    "Tautological assertion cannot fail when behavior breaks.",
    "Compare a computed SUT output against an independently derived expected value.",
  );

  addMatches(
    code,
    SAME_CALL_EXPECT,
    "self-derived-expectation",
    "test-smell",
    "error",
    "Actual and expected values invoke the exact same function call.",
    "Replace the expected side with a known literal or independent oracle.",
  );

  addMatches(
    code,
    CONDITIONAL_EXPECT,
    "no-conditional-expect",
    "test-smell",
    "error",
    "Assertion inside conditional branch silently passes if branch is skipped.",
    "Split into explicit test cases with unconditional assertions.",
  );

  addMatches(
    code,
    WALL_CLOCK,
    "no-elapsed-time-bound",
    "test-smell",
    "warn",
    "Wall-clock elapsed-time assertion flakes on shared CI runners.",
    "Assert logical ordering or move performance bounds to a dedicated R6 benchmark.",
  );

  addMatches(
    code,
    TEST_NONDETERMINISM,
    "no-test-nondeterminism",
    "test-smell",
    "warn",
    "Bare Math.random(), Date.now(), or new Date() introduces nondeterminism and defeats content-addressed test caching.",
    "Use a seeded RNG, fixed ISO date literal, or vi.setSystemTime / injectable clock to keep tests hermetic and cacheable.",
    3,
  );

  addMatches(
    code,
    IMPORTED_MUTATION,
    "no-imported-mutation",
    "test-smell",
    "warn",
    "Direct process.env/imported-object mutation leaks state across tests and breaks test-cache hermeticity.",
    "Pass configuration through options/bindings or a scoped override helper so tests remain hermetic and cacheable.",
  );

  addMatches(
    raw,
    TAILWIND_ASSERT,
    "no-styling-class-assertion",
    "test-smell",
    "warn",
    "Asserting Tailwind/CSS utility classes couples tests to styling refactors.",
    "Assert accessible role, ARIA state, or visible text; use R5 visual diff for layout.",
  );

  addMatches(
    raw,
    XPATH_OR_CSS,
    "ui-brittle-selector",
    "test-smell",
    "warn",
    "XPath or deep CSS chain breaks on harmless layout refactors.",
    "Prefer getByRole / getByLabel / getByText semantic locators.",
  );

  addMatches(
    code,
    PARAM_BRANCH,
    "no-parameter-branch",
    "test-smell",
    "warn",
    "Conditional branching inside test.each body obscures expected outcomes.",
    "Put expected outputs directly in the Tests-as-Data table rows.",
  );

  const existenceCount = code.match(EXISTENCE_ONLY)?.length ?? 0;
  if (existenceCount >= 2 && !/\.(?:toBe|toEqual|toStrictEqual|toHaveText|toHaveURL)\s*\(/.test(code)) {
    findings.push({
      id: `TS:existence-only:${file.rel}:1`,
      rule: "weak-asserts-existence",
      category: "test-smell",
      rung: "R0",
      severity: "warn",
      file: file.rel,
      line: 1,
      message: "Test file relies only on truthy/defined/not-null assertions.",
      fix: "Assert exact expected output values or externally observable state.",
    });
  }

  if (boundary === "e2e" && hasNetworkMock) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R7",
      targetRung: "R3",
      pattern: "e2e-with-mocked-network",
      reason: "Browser E2E test intercepts/mocks backend network calls — paying full E2E startup cost without real backend wiring.",
      replacement: "Move to R3 Component UI test (Testing Library / Playwright CT + strict MSW). Keep 1 unmocked R7 golden-path test.",
    });
  }

  if (boundary === "e2e" && testCases >= 5) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R7",
      targetRung: "R2",
      pattern: "e2e-combinatorial-matrix",
      reason: `E2E file contains ${testCases} cases — combinatorial validation/permission branches belong in R2 tables or R3 host/component suites.`,
      replacement: "Extract permission/validation cases into a CSV/YAML Tests-as-Data table at R2/R3 and keep only 1–2 golden journeys in R7.",
      forbiddenWarning: "Do not push down real OAuth redirects, CORS, or fresh-read persistence checks below R7.",
    });
  }

  if (boundary === "e2e" && (code.match(/\.click\(|\.fill\(|\.type\(/g)?.length ?? 0) >= 8) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R7",
      targetRung: "R3",
      pattern: "e2e-long-stateful-script",
      reason: "Long multi-step browser click script tests stateful transitions through a slow, brittle UI path.",
      replacement: "Model state transitions in an R3 Stateful MBT (fast-check commands / Hypothesis) or R5 Bombadil explorer.",
    });
  }

  if (boundary === "e2e" && TAILWIND_ASSERT.test(raw)) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R7",
      targetRung: "R5",
      pattern: "e2e-style-checks",
      reason: "E2E test checks styling classes instead of visual layout or semantic state.",
      replacement: "Use R3 role/ARIA assertions for state and R5 visual regression (/ui-diff, /gridlines) for pixels.",
    });
  }

  if (/integration/i.test(file.rel) && !hasRealDb && !hasRealBus && !HOST_SIGNAL.test(code) && !E2E_SIGNAL.test(code)) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R4",
      targetRung: "R2",
      pattern: "integration-without-real-engine",
      reason: "File lives in an integration test path but shows no real DB, bus, emulator, or HTTP host signals.",
      replacement: "Either move to fast R2 pure/table tests or wire a real isolated engine (Testcontainers / emulator) if testing storage/transport.",
      forbiddenWarning: "If this actually tests SQL constraints, Firestore rules, or broker DLQ, keep at R4 with a real engine.",
    });
  }

  if (boundary === "unit" && !hasTable && !hasPbt && testCases >= 8 && file.lines > 200) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R2",
      targetRung: "R2",
      pattern: "repetitive-unit-to-table-or-pbt",
      reason: `${testCases} example-based unit tests (${file.lines} lines) without table-driven data or property-based checks.`,
      replacement: "Collapse repetitive input/output cases into a Tests-as-Data CSV/YAML table or replace with 1–2 PBT invariants.",
    });
  }

  if (boundary === "unit" && doubleCount >= 3) {
    pushDowns.push({
      file: file.rel,
      line: 1,
      currentRung: "R2",
      targetRung: "R3",
      pattern: "mock-heavy-unit-to-deep-seam",
      reason: "Unit test uses heavy mocking across internal collaborators — fails refactors and misses integration bugs.",
      replacement: "Deepen the module, delete shallow unit tests ('replace, don't layer'), and test at the outer R2/R3 public seam.",
    });
  }

  return {
    record: {
      file: file.rel,
      language: file.language ?? "typescript",
      lines: file.lines,
      testCaseCount: testCases,
      boundary,
      rung,
      hasTable,
      hasPbt,
      hasMbt,
      hasRealDb,
      hasRealBus,
      hasNetworkMock,
    },
    findings,
    pushDowns,
  };
}

export function analyzeTests(repo: DiscoveredRepo): TestAnalysisResult {
  const inventory: TestFileRecord[] = [];
  const findings: Finding[] = [];
  const pushDownOpportunities: PushDownOpportunity[] = [];
  const repoHasEmulator = repo.signals.hasTestcontainersOrRealDb;

  findings.push(...scanVitestConfigs(repo));

  for (const file of repo.files) {
    if (!file.isTest || !file.language) continue;
    const result = scanSingleTestFile(file, repoHasEmulator);
    inventory.push(result.record);
    findings.push(...result.findings);
    pushDownOpportunities.push(...result.pushDowns);
  }

  return { inventory, findings, pushDownOpportunities };
}
