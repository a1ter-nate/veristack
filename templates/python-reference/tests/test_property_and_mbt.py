import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from order_lifecycle import (
    Accepted,
    Authorize,
    Cancel,
    OrderEvent,
    OrderState,
    Pending,
    PricingError,
    Rejected,
    Ship,
    calculate_total_cents,
    state_name,
    transition,
)


@given(
    unit_price=st.integers(min_value=0, max_value=10_000),
    qty=st.integers(min_value=0, max_value=500),
    discount=st.integers(min_value=0, max_value=100),
)
def test_pricing_is_bounded_and_exact_at_extremes(unit_price: int, qty: int, discount: int) -> None:
    gross = unit_price * qty
    total = calculate_total_cents(unit_price, qty, discount)
    assert 0 <= total <= gross
    assert calculate_total_cents(unit_price, qty, 0) == gross
    assert calculate_total_cents(unit_price, qty, 100) == 0


def test_pricing_rejects_negative_and_out_of_range_discounts() -> None:
    with pytest.raises(PricingError):
        calculate_total_cents(100, 1, 101)
    with pytest.raises(PricingError):
        calculate_total_cents(-1, 1, 0)


class OrderStateMachineModel(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.sut: OrderState = Pending(amount_cents=2500)
        self.model_phase: str = "pending"

    def _apply(self, event: OrderEvent) -> None:
        outcome = transition(self.sut, event)
        if isinstance(outcome, Accepted):
            self.sut = outcome.next_state
        elif isinstance(outcome, Rejected):
            self.sut = outcome.unchanged

    @rule(code=st.sampled_from(["AUTH-OK", "", " "]))
    def authorize(self, code: str) -> None:
        if self.model_phase == "pending" and code.strip():
            self.model_phase = "authorized"
        self._apply(Authorize(auth_code=code))

    @rule(tracking=st.sampled_from(["TRK-OK", "", " "]))
    def ship(self, tracking: str) -> None:
        if self.model_phase == "authorized" and tracking.strip():
            self.model_phase = "shipped"
        self._apply(Ship(tracking_id=tracking))

    @rule(reason=st.sampled_from(["customer", "", " "]))
    def cancel(self, reason: str) -> None:
        if self.model_phase in ("pending", "authorized") and reason.strip():
            self.model_phase = "cancelled"
        self._apply(Cancel(reason=reason))

    @invariant()
    def phase_matches_reference_model(self) -> None:
        assert state_name(self.sut) == self.model_phase


TestOrderMbt = OrderStateMachineModel.TestCase
TestOrderMbt.settings = settings(max_examples=80, stateful_step_count=20)
