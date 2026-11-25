import asyncio
import os
import tempfile


async def check_header_safely(header: str) -> bool:
    lock = asyncio.Lock()
    async with lock:
        return "no-store" in header.lower()


def read_text_safely(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_temp_safely(payload: str) -> str:
    fd, name = tempfile.mkstemp()
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(payload)
    return name
