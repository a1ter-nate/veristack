from dataclasses import dataclass
from typing import assert_never


@dataclass(frozen=True, slots=True)
class Pending:
    amount_cents: int


@dataclass(frozen=True, slots=True)
class Captured:
    amount_cents: int
    auth_code: str


@dataclass(frozen=True, slots=True)
class Failed:
    reason: str


PaymentState = Pending | Captured | Failed


def describe_payment(state: PaymentState) -> str:
    match state:
        case Pending(amount_cents=cents):
            return f"Pending {cents}"
        case Captured(auth_code=code):
            return f"Captured {code}"
        case Failed(reason=reason):
            return f"Failed: {reason}"
        case _:
            assert_never(state)
