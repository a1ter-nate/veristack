import re
import time
from collections import deque


class InvariantViolationError(RuntimeError):
    pass


def process_queue(items: list[str], pattern: str, timeout_s: float = 5.0) -> list[str]:
    if not pattern:
        raise InvariantViolationError("pattern must be non-empty")
    deadline = time.monotonic() + timeout_s
    compiled = re.compile(pattern)
    pending = deque(items)
    matched: list[str] = []
    while True:
        if not pending or time.monotonic() > deadline:
            break
        item = pending.popleft()
        if compiled.search(item):
            matched.append(item)
    return matched
