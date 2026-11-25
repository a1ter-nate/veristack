from collections import deque
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class TrackedState:
    state: OrderState
    ever_authorized: bool
    was_terminal: bool
    terminal_mutated: bool
    initial_amount: int


ALPHABET: tuple[OrderEvent, ...] = (
    Authorize("AUTH-1"),
    Authorize(""),
    Ship("TRK-1"),
    Ship(" "),
    Cancel("customer"),
    Cancel(""),
)


def test_exhaustive_formal_model_check_and_functional_cross_coverage_closure() -> None:
    initial = TrackedState(
        state=Pending(amount_cents=1500),
        ever_authorized=False,
        was_terminal=False,
        terminal_mutated=False,
        initial_amount=1500,
    )
    visited: set[TrackedState] = {initial}
    queue: deque[TrackedState] = deque([initial])
    reached_shipped = False
    reached_cancelled = False
    cross_bins: set[tuple[str, str, bool]] = set()

    while queue:
        cur = queue.popleft()
        assert not cur.terminal_mutated

        if isinstance(cur.state, Pending):
            assert cur.state.amount_cents == cur.initial_amount
        elif isinstance(cur.state, Authorized):
            assert cur.state.amount_cents == cur.initial_amount
            assert cur.state.auth_code.strip()
        elif isinstance(cur.state, Shipped):
            assert cur.ever_authorized
            assert cur.state.amount_cents == cur.initial_amount
            assert cur.state.auth_code.strip()
            assert cur.state.tracking_id.strip()
            reached_shipped = True
        elif isinstance(cur.state, Cancelled):
            assert cur.state.reason.strip()
            reached_cancelled = True

        for evt in ALPHABET:
            outcome = transition(cur.state, evt)
            accepted = isinstance(outcome, Accepted)
            next_order = outcome.next_state if isinstance(outcome, Accepted) else outcome.unchanged
            assert isinstance(outcome, (Accepted, Rejected))
            cross_bins.add((state_name(cur.state), type(evt).__name__, accepted))

            now_auth = isinstance(next_order, Authorized)
            now_term = isinstance(next_order, (Shipped, Cancelled))
            mutated = cur.was_terminal and next_order != cur.state
            nxt = TrackedState(
                state=next_order,
                ever_authorized=cur.ever_authorized or now_auth,
                was_terminal=cur.was_terminal or now_term,
                terminal_mutated=cur.terminal_mutated or mutated,
                initial_amount=cur.initial_amount,
            )
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)

    expected_legal_bins = {
        ("pending", "Authorize", True),
        ("pending", "Authorize", False),
        ("pending", "Ship", False),
        ("pending", "Cancel", True),
        ("pending", "Cancel", False),
        ("authorized", "Ship", True),
        ("authorized", "Ship", False),
        ("authorized", "Cancel", True),
        ("authorized", "Cancel", False),
        ("authorized", "Authorize", False),
        ("shipped", "Cancel", False),
        ("cancelled", "Authorize", False),
    }
    assert reached_shipped
    assert reached_cancelled
    assert expected_legal_bins.issubset(cross_bins)
    assert ("pending", "Ship", True) not in cross_bins
