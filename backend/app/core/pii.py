import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger("app.core.pii")


# Regex patterns for common PII
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "mac": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"),
    "uuid": re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "api_key": re.compile(
        r"\b(?:api[_-]?key|apikey)[\s:=]+[A-Za-z0-9_-]{20,}\b", re.IGNORECASE
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
}

# Fields that should always be redacted regardless of pattern match
SENSITIVE_FIELD_NAMES = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "session",
    "credit_card",
    "ssn",
    "social_security",
    "passport",
    "license",
    "raw_payload",
    "payload",
    "body",
    "request_body",
    "response_body",
}


def redact_pii(text: str, replacement: str = "[REDACTED]") -> str:
    """
    Redact PII from text using regex patterns.

    Args:
        text: Input text to redact
        replacement: String to replace PII with

    Returns:
        Text with PII redacted
    """
    if not text or not isinstance(text, str):
        return text

    result = text
    for pattern in PII_PATTERNS.values():
        result = pattern.sub(replacement, result)

    return result


def redact_dict(
    data: dict[str, Any],
    replacement: str = "[REDACTED]",
    sensitive_fields: set[str] | None = None,
) -> dict[str, Any]:
    """
    Redact PII from dictionary values recursively.

    Args:
        data: Dictionary to redact
        replacement: String to replace PII with
        sensitive_fields: Additional field names to always redact

    Returns:
        Dictionary with PII redacted
    """
    if not isinstance(data, dict):
        return data

    fields_to_redact = SENSITIVE_FIELD_NAMES.copy()
    if sensitive_fields:
        fields_to_redact.update(sensitive_fields)

    result = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if field name indicates sensitive data
        if any(sensitive in key_lower for sensitive in fields_to_redact):
            result[key] = replacement
        elif isinstance(value, str):
            result[key] = redact_pii(value, replacement)
        elif isinstance(value, dict):
            result[key] = redact_dict(value, replacement, sensitive_fields)
        elif isinstance(value, list):
            result[key] = [
                redact_dict(item, replacement, sensitive_fields)
                if isinstance(item, dict)
                else redact_pii(item, replacement)
                if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def hash_prompt(prompt: str) -> str:
    """
    Generate a SHA-256 hash of the prompt for logging instead of the prompt itself.

    Args:
        prompt: The prompt text to hash

    Returns:
        First 16 characters of SHA-256 hash
    """
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


class PIIRedactionContext:
    """
    Context manager for automatic PII redaction in logging.

    Usage:
        with PIIRedactionContext(logger):
            logger.info("User data: %s", user_data)  # Will be redacted
    """

    def __init__(
        self, logger_instance: logging.Logger, replacement: str = "[REDACTED]"
    ):
        self.logger = logger_instance
        self.replacement = replacement
        self.original_log = logger_instance._log

    def __enter__(self):
        def redacted_log(level, msg, args, **kwargs):
            if args:
                redacted_args = tuple(
                    redact_dict(arg)
                    if isinstance(arg, dict)
                    else redact_pii(arg)
                    if isinstance(arg, str)
                    else arg
                    for arg in args
                )
                self.original_log(level, msg, redacted_args, **kwargs)
            else:
                self.original_log(level, msg, args, **kwargs)

        self.logger._log = redacted_log
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger._log = self.original_log


def sanitize_for_llm(
    data: dict[str, Any], allowed_fields: set[str] | None = None
) -> dict[str, Any]:
    """
    Sanitize data for LLM consumption by removing PII and keeping only allowed fields.

    Args:
        data: Input data dictionary
        allowed_fields: Set of field names to allow (if None, uses default allowed fields)

    Returns:
        Sanitized dictionary safe for LLM consumption
    """
    if allowed_fields is None:
        allowed_fields = {
            "risk_score",
            "rating",
            "components",
            "source_ip",
            "event_frequency",
            "endpoints_touched",
            "endpoint_class",
            "historical_incident_count",
            "severity_hint",
            "rule_id",
            "rule_name",
            "technique_id",
            "detection_source",
            "severity",
            "confidence",
            "fidelity",
            "rule_accuracy_hint",
            "hostname",
            "username",
            "source_type",
        }

    sanitized = {}
    for key, value in data.items():
        if key in allowed_fields:
            if isinstance(value, str):
                sanitized[key] = redact_pii(value)
            elif isinstance(value, dict):
                sanitized[key] = sanitize_for_llm(value, allowed_fields)
            elif isinstance(value, list):
                sanitized[key] = [
                    sanitize_for_llm(item, allowed_fields)
                    if isinstance(item, dict)
                    else redact_pii(item)
                    if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value

    return sanitized
