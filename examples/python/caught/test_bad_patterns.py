import os
import time
import pytest
from state_machine_soup import describe_payment


@pytest.mark.skip(reason="flaky")
def test_skipped_tautology() -> None:
    assert True


def test_flaky_non_hermetic() -> None:
    os.environ["MODE"] = "test"
    now = time.time()
    time.sleep(0.05)
    assert describe_payment("pending" if now > 0 else "failed") == "Waiting"
