import pytest
from explicit_state_machine import (
    Captured,
    Failed,
    PaymentState,
    Pending,
    describe_payment,
)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (Pending(amount_cents=1200), "Pending 1200"),
        (Captured(amount_cents=1200, auth_code="AUTH-7"), "Captured AUTH-7"),
        (Failed(reason="declined"), "Failed: declined"),
    ],
)
def test_describe_payment_matrix(state: PaymentState, expected: str) -> None:
    assert describe_payment(state) == expected
