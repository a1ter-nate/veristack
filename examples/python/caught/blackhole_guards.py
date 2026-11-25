import json
from urllib.parse import urlparse


def unsafe_blackhole_py(raw_payload: str, target_url: str, port: int) -> tuple[object, str]:
    parsed_json: object = None
    try:
        parsed_json = json.loads(raw_payload)
    except json.JSONDecodeError:
        parsed_json = None
    parsed = urlparse(target_url)
    host_header = f"{parsed.hostname}:{port}"
    return parsed_json, host_header
