from dataclasses import dataclass
from enum import Enum
from typing import assert_never


class InvariantViolationError(RuntimeError):
    pass


def require_invariant(condition: bool, message: str) -> None:
    if not condition:
        raise InvariantViolationError(message)


@dataclass(frozen=True, slots=True)
class Pending:
    amount_cents: int


@dataclass(frozen=True, slots=True)
class Authorized:
    amount_cents: int
    auth_code: str


@dataclass(frozen=True, slots=True)
class Shipped:
    amount_cents: int
    auth_code: str
    tracking_id: str


@dataclass(frozen=True, slots=True)
class Cancelled:
    reason: str


OrderState = Pending | Authorized | Shipped | Cancelled


@dataclass(frozen=True, slots=True)
class Authorize:
    auth_code: str


@dataclass(frozen=True, slots=True)
class Ship:
    tracking_id: str


@dataclass(frozen=True, slots=True)
class Cancel:
    reason: str


OrderEvent = Authorize | Ship | Cancel


class RejectionCode(Enum):
    INVALID_AUTH_CODE = "INVALID_AUTH_CODE"
    INVALID_CANCEL_REASON = "INVALID_CANCEL_REASON"
    INVALID_TRACKING_ID = "INVALID_TRACKING_ID"
    CANNOT_SHIP_UNPAID = "CANNOT_SHIP_UNPAID"
    ALREADY_AUTHORIZED = "ALREADY_AUTHORIZED"
    TERMINAL_SHIPPED = "TERMINAL_SHIPPED"
    TERMINAL_CANCELLED = "TERMINAL_CANCELLED"


@dataclass(frozen=True, slots=True)
class Accepted:
    next_state: OrderState


@dataclass(frozen=True, slots=True)
class Rejected:
    code: RejectionCode
    unchanged: OrderState


TransitionOutcome = Accepted | Rejected


class PricingError(ValueError):
    pass


def transition(state: OrderState, event: OrderEvent) -> TransitionOutcome:
    match state:
        case Pending(amount_cents=amount_cents):
            require_invariant(amount_cents >= 0, "Pending amount must be non-negative.")
            match event:
                case Authorize(auth_code=auth_code):
                    if not auth_code.strip():
                        return Rejected(RejectionCode.INVALID_AUTH_CODE, state)
                    return Accepted(Authorized(amount_cents=amount_cents, auth_code=auth_code))
                case Cancel(reason=reason):
                    if not reason.strip():
                        return Rejected(RejectionCode.INVALID_CANCEL_REASON, state)
                    return Accepted(Cancelled(reason=reason))
                case Ship():
                    return Rejected(RejectionCode.CANNOT_SHIP_UNPAID, state)
                case _:
                    assert_never(event)
        case Authorized(amount_cents=amount_cents, auth_code=auth_code):
            require_invariant(bool(auth_code.strip()), "Authorized order must carry auth_code.")
            match event:
                case Ship(tracking_id=tracking_id):
                    if not tracking_id.strip():
                        return Rejected(RejectionCode.INVALID_TRACKING_ID, state)
                    return Accepted(
                        Shipped(
                            amount_cents=amount_cents,
                            auth_code=auth_code,
                            tracking_id=tracking_id,
                        )
                    )
                case Cancel(reason=reason):
                    if not reason.strip():
                        return Rejected(RejectionCode.INVALID_CANCEL_REASON, state)
                    return Accepted(Cancelled(reason=reason))
                case Authorize():
                    return Rejected(RejectionCode.ALREADY_AUTHORIZED, state)
                case _:
                    assert_never(event)
        case Shipped():
            return Rejected(RejectionCode.TERMINAL_SHIPPED, state)
        case Cancelled():
            return Rejected(RejectionCode.TERMINAL_CANCELLED, state)
        case _:
            assert_never(state)


def state_name(state: OrderState) -> str:
    match state:
        case Pending():
            return "pending"
        case Authorized():
            return "authorized"
        case Shipped():
            return "shipped"
        case Cancelled():
            return "cancelled"
        case _:
            assert_never(state)


def calculate_total_cents(unit_price_cents: int, quantity: int, discount_percent: int) -> int:
    if unit_price_cents < 0:
        raise PricingError("unit_price_cents must be non-negative")
    if quantity < 0:
        raise PricingError("quantity must be non-negative")
    if discount_percent < 0 or discount_percent > 100:
        raise PricingError("discount_percent must be in 0..100")
    gross = unit_price_cents * quantity
    discount = (gross * discount_percent) // 100
    total = gross - discount
    require_invariant(0 <= total <= gross, "Total must remain bounded within [0, gross].")
    return total
