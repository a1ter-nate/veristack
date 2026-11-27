import { Plugin } from "@veristack/plugin";
import { countDirectRuntimeDependencies } from "./interfaces-and-deps.ts";
import { analyzeTigerStyleCore, buildTigerStyleReport } from "./report.ts";

export { analyzeTigerAssertions } from "./assertions.ts";
export { analyzeTigerControlFlow } from "./control-flow.ts";
export {
  extractFunctionUnits,
  hasSafetyDirective,
  lineAtOffset,
  maskTigerCode,
  pushTigerFinding,
  resolveTigerLang,
  type FunctionUnit,
  type TigerLang,
} from "./helpers.ts";
export { analyzeTigerInterfacesAndDeps, countDirectRuntimeDependencies } from "./interfaces-and-deps.ts";
export { analyzeTigerNaming } from "./naming.ts";
export { analyzeTigerStyleCore as analyzeTigerStyle, buildTigerStyleReport } from "./report.ts";
export { analyzeTigerTypesAndAlloc } from "./types-and-alloc.ts";

export const tigerstylePlugin = Plugin.define({
  id: "veristack.plugin.tigerstyle",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.tigerstyle.rules",
        phase: "lint",
        run: (runCtx) => analyzeTigerStyleCore(runCtx.repo),
      });
    });
    ctx.reporter.transform((ed) => {
      ed.add({
        id: "veristack.tigerstyle.reporter",
        buildTigerStyle: buildTigerStyleReport,
        countDirectDeps: countDirectRuntimeDependencies,
      });
    });
  },
});

export default tigerstylePlugin;
