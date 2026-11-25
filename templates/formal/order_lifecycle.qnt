module order_lifecycle {
  type Phase = "pending" | "authorized" | "shipped" | "cancelled"

  var phase: Phase
  var amount_cents: int
  var initial_amount_cents: int
  var auth_code: str
  var tracking_id: str
  var cancel_reason: str
  var paid_before_ship: bool

  action init = all {
    phase' = "pending",
    amount_cents' = 1500,
    initial_amount_cents' = 1500,
    auth_code' = "",
    tracking_id' = "",
    cancel_reason' = "",
    paid_before_ship' = false,
  }

  action authorize(code: str): bool = all {
    phase == "pending",
    code != "",
    phase' = "authorized",
    amount_cents' = amount_cents,
    initial_amount_cents' = initial_amount_cents,
    auth_code' = code,
    tracking_id' = tracking_id,
    cancel_reason' = cancel_reason,
    paid_before_ship' = true,
  }

  action ship(tracking: str): bool = all {
    phase == "authorized",
    tracking != "",
    phase' = "shipped",
    amount_cents' = amount_cents,
    initial_amount_cents' = initial_amount_cents,
    auth_code' = auth_code,
    tracking_id' = tracking,
    cancel_reason' = cancel_reason,
    paid_before_ship' = paid_before_ship,
  }

  action cancel(reason: str): bool = all {
    phase == "pending" or phase == "authorized",
    reason != "",
    phase' = "cancelled",
    amount_cents' = amount_cents,
    initial_amount_cents' = initial_amount_cents,
    auth_code' = auth_code,
    tracking_id' = tracking_id,
    cancel_reason' = reason,
    paid_before_ship' = paid_before_ship,
  }

  action stutter = all {
    phase' = phase,
    amount_cents' = amount_cents,
    initial_amount_cents' = initial_amount_cents,
    auth_code' = auth_code,
    tracking_id' = tracking_id,
    cancel_reason' = cancel_reason,
    paid_before_ship' = paid_before_ship,
  }

  action step = any {
    authorize("AUTH-1"),
    ship("TRK-1"),
    cancel("customer"),
    stutter,
  }

  val inv_no_unpaid_shipment: bool =
    (phase == "shipped") implies (paid_before_ship and auth_code != "" and tracking_id != "")

  val inv_authorized_has_code: bool =
    (phase == "authorized") implies (auth_code != "" and tracking_id == "")

  val inv_cancelled_has_reason: bool =
    (phase == "cancelled") implies (cancel_reason != "")

  val inv_amount_preserved: bool =
    amount_cents == initial_amount_cents and amount_cents >= 0

  val safety_invariants: bool = all {
    inv_no_unpaid_shipment,
    inv_authorized_has_code,
    inv_cancelled_has_reason,
    inv_amount_preserved,
  }
}
