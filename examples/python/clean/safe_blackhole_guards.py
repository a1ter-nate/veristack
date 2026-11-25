import json
from urllib.parse import urlparse


def safe_blackhole_py(
    raw_payload: str, target_url: str, port: int
) -> tuple[object, str]:
    parsed_json: object = None
    try:
        parsed_json = json.loads(raw_payload)
    except (json.JSONDecodeError, RecursionError):
        parsed_json = None
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    host_header = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return parsed_json, host_header
