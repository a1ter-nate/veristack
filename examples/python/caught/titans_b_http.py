from typing import Protocol


class ResponseProto(Protocol):
    headers: dict[str, str]

    def delete_cookie(self, key: str) -> None: ...


def unsafe_http_and_jwt(
    decode_jwt: object,
    response: ResponseProto,
    body: str,
) -> bytes:
    verify_signature = False
    response.headers["Vary"] = "Accept-Encoding"
    response.delete_cookie("session")
    response.headers["Content-Length"] = str(len(body))
    _ = (decode_jwt, verify_signature)
    return body.encode("ascii")
