import { lineOf, maskCode, Plugin, type Finding, type ScannedFile } from "@veristack/plugin";

const GO_SWALLOW_ERR = /\bif\s+err\s*!=\s*nil\s*\{\s*\}/g;
const GO_UNSAFE_PTR = /\bunsafe\.Pointer\b/g;
const GO_BARE_NOLINT = /\/\/\s*nolint(?:\s*$|\s*\n)/gm;

export function scanGoStructure(file: ScannedFile): Finding[] {
  if (!file.content || file.isTest) return [];
  const findings: Finding[] = [];
  const goCode = maskCode(file.content, "go");
  const goRules: ReadonlyArray<[string, RegExp, string, Finding["category"], string, string, string]> = [
    [goCode, GO_SWALLOW_ERR, "no-swallowing-catch", "structure", "Empty 'if err != nil {}' block silently swallows Go error.", "Return or wrap the error explicitly with fmt.Errorf(..., err).", "go-swallow-err"],
    [goCode, GO_UNSAFE_PTR, "no-unsafe-pointer", "structure", "unsafe.Pointer bypasses Go memory and type safety.", "Use safe typed Go values/slices instead of unsafe.Pointer.", "go-unsafe"],
    [file.content, GO_BARE_NOLINT, "no-bare-suppression", "cheat", "Bare //nolint suppression hides Go linter diagnostics without rule or justification.", "Fix the diagnostic or name the specific linter with justification.", "go-nolint"],
  ];
  for (const [src, re, rule, category, message, fix, tag] of goRules) {
    for (const match of src.matchAll(re)) {
      const line = lineOf(file.content, match.index ?? 0);
      findings.push({ id: `ST:${tag}:${file.rel}:${line}`, rule, category, rung: "R0", severity: "error", file: file.rel, line, message, fix });
    }
  }
  return findings;
}

export const langGoPlugin = Plugin.define({
  id: "veristack.plugin.lang-go",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "go",
        extensions: [".go"],
        scanStructure: scanGoStructure,
      });
    });
  },
});

export default langGoPlugin;
