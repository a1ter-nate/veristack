module OrderLifecycleFormal {
  datatype OrderState =
    | Pending(amountCents: nat)
    | Authorized(amountCents: nat, authCode: string)
    | Shipped(amountCents: nat, authCode: string, trackingId: string)
    | Cancelled(reason: string)

  datatype OrderEvent =
    | Authorize(authCode: string)
    | Ship(trackingId: string)
    | Cancel(reason: string)

  predicate ValidState(s: OrderState) {
    match s
    case Pending(_) => true
    case Authorized(_, code) => |code| > 0
    case Shipped(_, code, tracking) => |code| > 0 && |tracking| > 0
    case Cancelled(reason) => |reason| > 0
  }

  function Transition(s: OrderState, e: OrderEvent): OrderState
    requires ValidState(s)
    ensures ValidState(Transition(s, e))
    ensures s.Shipped? ==> Transition(s, e) == s
    ensures s.Cancelled? ==> Transition(s, e) == s
    ensures s.Pending? && e.Ship? ==> Transition(s, e) == s
  {
    match (s, e)
    case (Pending(amt), Authorize(code)) =>
      if |code| > 0 then Authorized(amt, code) else s
    case (Pending(_), Cancel(reason)) =>
      if |reason| > 0 then Cancelled(reason) else s
    case (Pending(_), Ship(_)) => s
    case (Authorized(amt, code), Ship(tracking)) =>
      if |tracking| > 0 then Shipped(amt, code, tracking) else s
    case (Authorized(_, _), Cancel(reason)) =>
      if |reason| > 0 then Cancelled(reason) else s
    case (Authorized(_, _), Authorize(_)) => s
    case (Shipped(_, _, _), _) => s
    case (Cancelled(_), _) => s
  }

  function CalculateTotalCents(unitPriceCents: nat, quantity: nat, discountPercent: nat): nat
    requires discountPercent <= 100
    ensures CalculateTotalCents(unitPriceCents, quantity, discountPercent) <= unitPriceCents * quantity
    ensures discountPercent == 0 ==> CalculateTotalCents(unitPriceCents, quantity, discountPercent) == unitPriceCents * quantity
    ensures discountPercent == 100 ==> CalculateTotalCents(unitPriceCents, quantity, discountPercent) == 0
  {
    var gross := unitPriceCents * quantity;
    var discount := (gross * discountPercent) / 100;
    gross - discount
  }
}
