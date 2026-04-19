from __future__ import annotations

import logging

from src.logging_utils import DEFAULT_LOG_FORMAT, configure_logging, get_logger, reset_request_id, set_request_id


def test_configure_logging_updates_existing_root_level():
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    try:
        if not root.handlers:
            root.addHandler(logging.StreamHandler())
        root.setLevel(logging.WARNING)
        configure_logging("debug")
        assert root.level == logging.DEBUG
    finally:
        root.handlers = original_handlers
        root.setLevel(original_level)


def test_configure_logging_normalizes_existing_handler_formatter_and_request_id():
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        root.handlers = [handler]
        configure_logging("info")
        token = set_request_id("req-123")
        try:
            record = logging.LogRecord("cyber.test", logging.INFO, __file__, 1, "message", (), None)
            handler.filters[0].filter(record)
            assert record.request_id == "req-123"
        finally:
            reset_request_id(token)
        assert handler.formatter is not None
        assert handler.formatter._fmt == DEFAULT_LOG_FORMAT
    finally:
        root.handlers = original_handlers
        root.setLevel(original_level)


def test_get_logger_returns_named_logger():
    logger = get_logger("cyber.test")
    assert logger.name == "cyber.test"
    assert DEFAULT_LOG_FORMAT.endswith("%(message)s")
    assert "%(request_id)s" in DEFAULT_LOG_FORMAT
