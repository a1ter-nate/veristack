import re
import time


def process_queue(queue: list[str], pattern: str) -> list[str]:
    assert len(pattern) > 0
    started = time.time()
    matched: list[str] = []
    while len(queue) > 0:
        item = queue.pop(0)
        compiled = re.compile(pattern)
        if compiled.search(item):
            matched.append(item)
    if time.time() - started > 5.0:
        return []
    return matched


def poll_forever(check_ready: object) -> None:
    while True:
        if check_ready:
            break
