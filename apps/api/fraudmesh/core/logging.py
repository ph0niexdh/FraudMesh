"""Structured JSON logging with request/event/case correlation ids."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
event_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("event_id", default=None)
case_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("case_id", default=None)

# Keys that must never reach a log line even if a caller passes them in ``extra``.
_REDACT = {"password", "otp", "code", "token", "refresh_token", "access_token", "totp_secret", "secret"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, var in (("request_id", request_id_var), ("event_id", event_id_var), ("case_id", case_id_var)):
            value = var.get()
            if value:
                payload[key] = value
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            for k, v in extra.items():
                payload[k] = "[REDACTED]" if k.lower() in _REDACT else v
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("uvicorn.access", "neo4j", "httpx", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def log(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"fields": fields})
