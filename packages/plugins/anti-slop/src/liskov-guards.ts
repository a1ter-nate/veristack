import { lineOf, maskCode, type DiscoveredRepo, type Finding, type ScannedFile } from "@veristack/plugin";

function findMatchingBrace(text: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function checkTsLiskov(file: ScannedFile, masked: string, findings: Finding[]): void {
  if (!masked) return;
  const ifaceReturnTypes = new Map<string, Map<string, string>>();
  for (const im of masked.matchAll(/\b(?:interface|abstract\s+class)\s+([A-Za-z_$]\w*)(?:\s*<[^>]+>)?\s*\{/g)) {
    const ifaceName = im[1] ?? "";
    const openIdx = (im.index ?? 0) + im[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (!ifaceName || closeIdx < 0) continue;
    const body = file.content.slice(openIdx + 1, closeIdx);
    const methods = new Map<string, string>();
    for (const mm of body.matchAll(/(?:^|\n)\s*(?:(?:public|protected|abstract)\s+)*([a-zA-Z_$]\w*)\s*\([^)]*\)\s*:\s*([^;\n{]+)/g)) {
      const mName = mm[1] ?? "";
      const ret = (mm[2] ?? "").trim();
      if (mName && ret && !/^(?:if|for|while|switch|catch|constructor)$/.test(mName)) methods.set(mName, ret);
    }
    if (methods.size > 0) ifaceReturnTypes.set(ifaceName, methods);
  }

  for (const cm of masked.matchAll(/\bclass\s+([A-Za-z_$]\w*)(?:\s*<[^>]+>)?\s+(?:extends|implements)\s+([A-Za-z0-9_$,\s<>]+?)\s*\{/g)) {
    const clsName = cm[1] ?? "";
    const parents = (cm[2] ?? "").split(/[,\s]+/).map((p) => p.replace(/<.*$/, "").trim()).filter(Boolean);
    const openIdx = (cm.index ?? 0) + cm[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;
    const clsMasked = masked.slice(openIdx + 1, closeIdx);
    const clsRaw = file.content.slice(openIdx + 1, closeIdx);
    for (const mm of clsMasked.matchAll(/(?:^|\n)\s*(?:(?:public|protected|private|async|override)\s+)*([a-zA-Z_$]\w*)\s*\([^)]*\)(?:\s*:\s*([^{\n]+))?\s*\{/g)) {
      const mName = mm[1] ?? "";
      if (!mName || /^(?:if|for|while|switch|catch|constructor)$/.test(mName)) continue;
      const mOpen = (mm.index ?? 0) + mm[0].length - 1;
      const mClose = findMatchingBrace(clsMasked, mOpen);
      if (mClose < 0) continue;
      const bodyRaw = clsRaw.slice(mOpen + 1, mClose);
      const absOff = openIdx + 1 + (mm.index ?? 0);
      const line = lineOf(file.content, absOff);
      if (/\bthrow\s+new\s+(?:NotImplementedError|UnsupportedOperationError)\b|\bthrow\s+new\s+Error\s*\(\s*["'](?:not implemented|unsupported)/i.test(bodyRaw)) {
        findings.push({
          id: `LSP:unimpl:${file.rel}:${line}`, rule: "liskov-unimplemented-override", category: "structure", rung: "R1",
          severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
          message: `Class '${clsName}.${mName}()' violates Liskov substitutability by throwing NotImplemented/Unsupported on a port/interface method.`,
          fix: "Split the interface (Interface Segregation) or implement the full behavioral contract.",
        });
      }
      const retRaw = (mm[2] ?? "").trim();
      for (const parent of parents) {
        const expectedRet = ifaceReturnTypes.get(parent)?.get(mName);
        if (!expectedRet || !retRaw) continue;
        const baseAllowsNull = /\b(?:null|undefined)\b/.test(expectedRet);
        const subAllowsNull = /\b(?:null|undefined)\b/.test(retRaw);
        if (!baseAllowsNull && subAllowsNull) {
          findings.push({
            id: `LSP:widen:${file.rel}:${line}`, rule: "liskov-widened-return-type", category: "structure", rung: "R1",
            severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
            message: `Method '${clsName}.${mName}()' widens return type to nullable '${retRaw}' beyond '${parent}.${mName}(): ${expectedRet}'.`,
            fix: "Return a value conforming to the parent contract or update the port signature explicitly.",
          });
        }
      }
      if (/\boverride\b/.test(mm[0]) && /\bthrow\s+new\s+(?:RangeError|TypeError)\b/.test(bodyRaw)) {
        findings.push({
          id: `LSP:precond:${file.rel}:${line}`, rule: "liskov-strengthened-precondition", category: "structure", rung: "R1",
          severity: "warn", soundness: "hygiene-lint", file: file.rel, line,
          message: `Override '${clsName}.${mName}()' adds a runtime RangeError/TypeError precondition guard — verify it does not strengthen preconditions beyond its base contract.`,
          fix: "Accept all inputs valid under the base contract (contravariant preconditions).",
        });
      }
    }
  }
}

function checkCsharpLiskov(file: ScannedFile, masked: string, findings: Finding[]): void {
  for (const cm of masked.matchAll(/\bclass\s+([A-Za-z_]\w*)\s*:\s*([A-Za-z0-9_.,\s<>]+?)\s*\{/g)) {
    const clsName = cm[1] ?? "";
    const openIdx = (cm.index ?? 0) + cm[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;
    const clsRaw = file.content.slice(openIdx + 1, closeIdx);
    for (const tm of clsRaw.matchAll(/\bthrow\s+new\s+(?:NotImplementedException|NotSupportedException)\s*\(/g)) {
      const line = lineOf(file.content, openIdx + 1 + (tm.index ?? 0));
      findings.push({
        id: `LSP:cs-unimpl:${file.rel}:${line}`, rule: "liskov-unimplemented-override", category: "structure", rung: "R1",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
        message: `C# implementation '${clsName}' throws ${tm[0].includes("NotSupported") ? "NotSupportedException" : "NotImplementedException"}, violating Liskov substitutability.`,
        fix: "Segregate the interface or implement the contract method completely.",
      });
    }
  }
}

function checkRustLiskov(file: ScannedFile, masked: string, findings: Finding[]): void {
  for (const im of masked.matchAll(/\bimpl(?:<[^>]+>)?\s+[A-Za-z0-9_:<>]+\s+for\s+([A-Za-z0-9_:<>]+)\s*\{/g)) {
    const typeName = im[1] ?? "";
    const openIdx = (im.index ?? 0) + im[0].length - 1;
    const closeIdx = findMatchingBrace(masked, openIdx);
    if (closeIdx < 0) continue;
    const body = masked.slice(openIdx + 1, closeIdx);
    for (const um of body.matchAll(/\b(?:unimplemented|todo)!\s*\(/g)) {
      const line = lineOf(file.content, openIdx + 1 + (um.index ?? 0));
      findings.push({
        id: `LSP:rs-unimpl:${file.rel}:${line}`, rule: "liskov-unimplemented-override", category: "structure", rung: "R1",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
        message: `Trait impl for '${typeName}' panics via ${um[0]}), breaking behavioral substitutability.`,
        fix: "Split the trait or implement the trait method without panicking stubs.",
      });
    }
  }
}

function checkPythonLiskov(file: ScannedFile, findings: Finding[]): void {
  const lines = file.content.split(/\r?\n/);
  let inConcreteSub = false;
  let subIndent = 0;
  let clsName = "";
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i] ?? "";
    const cls = /^(\s*)class\s+([A-Za-z_]\w*)\s*\(([^)]+)\)\s*:/.exec(ln);
    if (cls) {
      const bases = cls[3] ?? "";
      inConcreteSub = !/\b(?:ABC|ABCMeta|Protocol|object|Exception|BaseException)\b/.test(bases);
      subIndent = (cls[1] ?? "").length;
      clsName = cls[2] ?? "";
      continue;
    }
    if (inConcreteSub && ln.trim() && ln.length - ln.trimStart().length <= subIndent) inConcreteSub = false;
    if (!inConcreteSub) continue;
    if (/^\s*raise\s+NotImplementedError\b/.test(ln)) {
      const prevLines = lines.slice(Math.max(0, i - 4), i).join("\n");
      if (/@abstractmethod\b/.test(prevLines)) continue;
      findings.push({
        id: `LSP:py-unimpl:${file.rel}:${i + 1}`, rule: "liskov-unimplemented-override", category: "structure", rung: "R1",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line: i + 1,
        message: `Concrete subclass '${clsName}' raises NotImplementedError, violating Liskov behavioral subtyping.`,
        fix: "Split the Protocol/ABC or implement the inherited method.",
      });
    }
  }
}

export function analyzeLiskovSubtyping(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("repo.root is required.");
  const findings: Finding[] = [];
  for (const file of repo.files) {
    if (!file.language || file.isTest || file.isStub) continue;
    const masked = maskCode(file.content, file.language, true);
    if (file.language === "typescript" || file.language === "javascript") checkTsLiskov(file, masked, findings);
    else if (file.language === "csharp") checkCsharpLiskov(file, masked, findings);
    else if (file.language === "rust") checkRustLiskov(file, masked, findings);
    else if (file.language === "python") checkPythonLiskov(file, findings);
  }
  return findings;
}
