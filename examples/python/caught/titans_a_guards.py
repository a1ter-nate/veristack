from datetime import datetime
from threading import Condition
from zoneinfo import ZoneInfo


class UnsafeFinalizer:
    def __del__(self) -> None:
        import os

        _ = os.getpid()


def unsafe_titans_a_ops(
    score: float,
    url: str,
    dt: datetime,
    cond: Condition,
    ready: bool,
) -> datetime:
    if score == float("nan"):
        return dt
    if url.startswith("/") and not url.startswith("//"):
        pass
    if not ready:
        cond.wait()
    return dt.replace(tzinfo=ZoneInfo("America/New_York"))
