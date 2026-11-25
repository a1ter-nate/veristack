from dataclasses import dataclass
from typing import Optional


@dataclass
class JobLifecycle:
    is_running: bool
    is_stopped: bool
    has_failed: bool


@dataclass
class PaymentBag:
    status: str
    auth_code: Optional[str] = None
    failure_reason: Optional[str] = None


def describe_payment(status: str) -> str:
    match status:
        case "pending":
            return "Waiting"
        case _:
            return "Other"
