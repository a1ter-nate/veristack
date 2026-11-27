module veristack_gates {
  type RungGrade = "not-covered" | "over-budget" | "poorly-covered" | "well-covered" | "not-applicable"

  pure def gradeRank(g: RungGrade): int =
    if (g == "not-covered") 0
    else if (g == "over-budget") 1
    else if (g == "poorly-covered") 2
    else if (g == "well-covered") 3
    else -1

  pure def isMonotonicRungStep(baseGrade: RungGrade, curGrade: RungGrade, baseCi: bool, curCi: bool): bool =
    if (baseGrade == "not-applicable") true
    else if (curGrade == "not-applicable") false
    else if (gradeRank(curGrade) < gradeRank(baseGrade)) false
    else if (baseCi and not(curCi)) false
    else true

  pure def isReceiptValid(
    hmacValid: bool,
    exitCode: int,
    treeMatches: bool,
    headMatches: bool,
    testsPassed: int,
    testsFailed: int,
    canaryRequired: bool,
    canaryPassed: bool,
    canaryKillPct: int,
    canaryFloorPct: int,
    canaryInvalid: int
  ): bool =
    hmacValid
    and exitCode == 0
    and treeMatches
    and headMatches
    and testsPassed > 0
    and testsFailed == 0
    and (not(canaryRequired) or (canaryPassed and canaryKillPct >= canaryFloorPct and canaryInvalid == 0))

  var curGrade: RungGrade
  var curCi: bool
  var receiptAccepted: bool

  action init = all {
    curGrade' = "well-covered",
    curCi' = true,
    receiptAccepted' = true,
  }

  action stepKeepStrict = all {
    curGrade' = "well-covered",
    curCi' = true,
    receiptAccepted' = isReceiptValid(true, 0, true, true, 1, 0, true, true, 90, 75, 0),
  }

  val monotonicInvariant = isMonotonicRungStep("well-covered", curGrade, true, curCi)
  val strictReceiptInvariant = receiptAccepted
}
