from typing import Protocol


class SafeResponseProto(Protocol):
    headers: dict[str, str]

    def delete_cookie(
        self, key: str, *, path: str, secure: bool, samesite: str
    ) -> None: ...


def safe_http_and_jwt(response: SafeResponseProto, body: str) -> bytes:
    encoded = body.encode("utf-8")
    existing_vary = response.headers.get("Vary", "")
    response.headers["Vary"] = (
        f"{existing_vary}, Accept-Encoding" if existing_vary else "Accept-Encoding"
    )
    response.delete_cookie("session", path="/", secure=True, samesite="lax")
    response.headers["Content-Length"] = str(len(encoded))
    return encoded
