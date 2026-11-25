import json
from pathlib import Path
from typing import TypedDict

import pytest

from order_lifecycle import (
    Accepted,
    Authorize,
    Authorized,
    Cancel,
    Cancelled,
    OrderEvent,
    OrderState,
    Pending,
    Rejected,
    Ship,
    Shipped,
    state_name,
    transition,
)


class TransitionRow(TypedDict):
    name: str
    initial: str
    event: str
    arg: str
    accepted: bool
    expected: str
    error_code: str


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "transitions.json"
ROWS: list[TransitionRow] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def build_state(kind: str) -> OrderState:
    if kind == "pending":
        return Pending(amount_cents=1500)
    if kind == "authorized":
        return Authorized(amount_cents=1500, auth_code="AUTH-0")
    if kind == "shipped":
        return Shipped(amount_cents=1500, auth_code="AUTH-0", tracking_id="TRK-0")
    if kind == "cancelled":
        return Cancelled(reason="init")
    raise ValueError(f"unknown state: {kind}")


def build_event(kind: str, arg: str) -> OrderEvent:
    if kind == "authorize":
        return Authorize(auth_code=arg)
    if kind == "ship":
        return Ship(tracking_id=arg)
    if kind == "cancel":
        return Cancel(reason=arg)
    raise ValueError(f"unknown event: {kind}")


@pytest.mark.parametrize("row", ROWS, ids=[r["name"] for r in ROWS])
def test_transition_matrix_matches_tests_as_data_json(row: TransitionRow) -> None:
    initial = build_state(row["initial"])
    event = build_event(row["event"], row["arg"])
    outcome = transition(initial, event)

    if row["accepted"]:
        assert isinstance(outcome, Accepted)
        assert state_name(outcome.next_state) == row["expected"]
    else:
        assert isinstance(outcome, Rejected)
        assert outcome.code.value == row["error_code"]
        assert state_name(outcome.unchanged) == row["expected"]
        assert outcome.unchanged == initial
