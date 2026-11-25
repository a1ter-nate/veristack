import math
import os
import sys
from datetime import UTC, datetime
from threading import Condition


class SafeFinalizer:
    def __del__(self) -> None:
        if sys.is_finalizing():
            return
        _ = os.getpid()


def safe_titans_a_ops(
    score: float,
    url: str,
    dt: datetime,
    cond: Condition,
    ready: list[bool],
) -> datetime:
    if math.isnan(score):
        return dt
    if url.startswith("/") and not url.startswith("//") and "\\" not in url:
        pass
    while not ready[0]:
        cond.wait()
    return dt.astimezone(UTC)
