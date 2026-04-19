from __future__ import annotations

import contextvars
import logging
import os


DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] [req=%(request_id)s] %(message)s"
_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _REQUEST_ID.get()
        return True


def set_request_id(request_id: str) -> contextvars.Token[str]:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: contextvars.Token[str]) -> None:
    _REQUEST_ID.reset(token)


def configure_logging(level: str | None = None) -> None:
    resolved_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(level=resolved_level, format=DEFAULT_LOG_FORMAT)
    root_logger.setLevel(resolved_level)
    _configure_root_handlers(root_logger)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def _configure_root_handlers(root_logger: logging.Logger) -> None:
    for handler in root_logger.handlers:
        _ensure_request_id_filter(handler)
        handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))


def _ensure_request_id_filter(handler: logging.Handler) -> None:
    if any(isinstance(existing, RequestIdFilter) for existing in handler.filters):
        return
    handler.addFilter(RequestIdFilter())
