from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import get_settings


class RequestSizeLimitMiddleware:
    """Enforces the byte limit even when the client omits Content-Length."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/v1/chat/completions"
        ):
            await self.app(scope, receive, send)
            return

        max_bytes = get_settings().max_request_bytes
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header")
                return
            if declared_size < 0:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header")
                return
            if declared_size > max_bytes:
                await self._reject(
                    scope, receive, send, 413, "Request exceeds configured size limit"
                )
                return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > max_bytes:
                await self._reject(
                    scope, receive, send, 413, "Request exceeds configured size limit"
                )
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send, status: int, reason: str
    ) -> None:
        response = JSONResponse(status_code=status, content={"detail": reason})
        await response(scope, receive, send)
