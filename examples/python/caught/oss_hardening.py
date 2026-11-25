import asyncio
import os
import tempfile

GLOBAL_LOCK = asyncio.Lock()


def bad_io_and_auth(path: str, qs: object, params: dict[str, object], header: str) -> str:
    if os.environ.get("DEBUG_MODE"):
        return "bypass"
    handle = open(path, "r")
    _fd, _name = tempfile.mkstemp()
    qs.annotate(**params)
    if "no-store" in header:
        return ""
    try:
        return handle.read()
    except Exception:
        handle.close()
        raise
