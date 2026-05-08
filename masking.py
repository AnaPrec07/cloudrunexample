"""
masking.py — DataMasker: foundational PII control layer.

Every component that writes to logs, traces, Firestore, metrics, or HTTP
responses MUST call masker.mask_text() or masker.mask_dict() first.
This is the application's primary defense-in-depth control, not an afterthought.

Masking points (referenced by number in main.py):
  [M1] Incoming request body — before logging raw request in middleware
  [M2] Agent input — strip PII before the message reaches the model
  [M3] Agent output — before returning to caller and before session write
  [M4] Session history writes — before persisting turns to Firestore
  [M5] Log entries — all structured log payloads via mask_dict()
  [M6] Trace span attributes — user_id hashed (SHA-256 first 8 chars)
  [M7] Evaluation inputs/outputs — mask test content before logging results
  [M8] Token cost logs — defense-in-depth even though no PII expected
  [M9] Error messages — log full exception internally; return only safe code
"""

import re
import hashlib
import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Regex patterns ─────────────────────────────────────────────────────────────
# Panama cédula formats:
#   National:     8-123-45678
#   Foreign res.: PE-8-12345 or E-8-12345
#   Naturalized:  N-20-12345
_CEDULA_RE = [
    re.compile(r"\b\d{1,2}-\d{3,4}-\d{4,6}\b"),
    re.compile(r"\b(?:PE|E|N)-\d{1,2}-\d{3,6}\b", re.IGNORECASE),
]
_EMAIL_RE = re.compile(r"\b[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}\b")
# Phone: 7-15 digit sequences; broad pattern catches international formats
_PHONE_RE = re.compile(r"\b(?:\+?\d[\d\s\-().]{6,14}\d)\b")
_CARD_RE  = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
# IBAN: 2-letter country code + 2 digits + up to 30 alphanumeric
_IBAN_RE  = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")

# Fields whose values are always fully redacted regardless of content.
# Add domain-specific terms (e.g., "cuenta", "clave") as your data model grows.
_SENSITIVE_KEYS: set[str] = {
    "password", "token", "secret", "api_key", "authorization",
    "cedula", "nit", "ruc", "ssn", "dob", "credit_card",
    "cuenta", "clave", "contrasena",
}

USE_CLOUD_DLP = os.getenv("USE_CLOUD_DLP", "false").lower() == "true"
GCP_PROJECT   = os.getenv("GCP_PROJECT", "")

# ── Optional Cloud DLP client ──────────────────────────────────────────────────
# Initialized once at module load so we pay the SDK init cost once, not per call.
_dlp_client = None
if USE_CLOUD_DLP:
    try:
        from google.cloud import dlp_v2  # type: ignore
        _dlp_client = dlp_v2.DlpServiceClient()
        logger.info("Cloud DLP client initialized")
    except Exception as exc:
        # Non-fatal: regex path covers the baseline; DLP is an enhancement.
        logger.warning("Cloud DLP unavailable, falling back to regex: %s", exc)


class DataMasker:
    """
    Stateless PII masking utility.
    No instance state → one module-level singleton is safe across async workers.
    """

    def mask_text(self, text: str) -> str:
        """
        Apply all masking strategies to a freeform string.
        DLP runs first (higher confidence); regex always runs as fallback.
        """
        if not isinstance(text, str):
            return text

        if USE_CLOUD_DLP and _dlp_client:
            text = self._dlp_mask(text)

        # Regex masks always run — even after DLP — for defense-in-depth [M2]
        for pattern in _CEDULA_RE:
            text = pattern.sub("[CÉDULA]", text)
        text = _EMAIL_RE.sub(self._mask_email, text)
        text = _PHONE_RE.sub("[PHONE]", text)
        text = _IBAN_RE.sub("[IBAN]", text)
        # Credit card: validate with Luhn before masking to avoid false positives
        text = _CARD_RE.sub(self._maybe_mask_card, text)
        return text

    def mask_dict(self, data: Any, extra_keys: set[str] | None = None) -> Any:
        """
        Recursively walk a nested dict/list/str structure.
        - Keys matching the sensitive set → value replaced with [REDACTED]
        - All other string values → run through mask_text()
        - Non-string scalars (int, float, bool, datetime) → pass through unchanged

        Why recursive: Firestore documents and log payloads are often nested
        (e.g., session.history[n].text). A shallow walk misses PII in sub-fields.
        """
        keys = _SENSITIVE_KEYS | (extra_keys or set())
        return self._walk(data, keys)

    def hash_id(self, value: str) -> str:
        """
        SHA-256 truncated to 8 hex chars.
        Used for user_id in trace spans and Firestore [M6] — never store
        plaintext user identity in an observability backend.
        """
        return hashlib.sha256(value.encode()).hexdigest()[:8]

    # ── Private helpers ────────────────────────────────────────────────────────

    def _walk(self, node: Any, keys: set[str]) -> Any:
        if isinstance(node, dict):
            return {
                k: "[REDACTED]" if k.lower() in keys else self._walk(v, keys)
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [self._walk(item, keys) for item in node]
        if isinstance(node, str):
            return self.mask_text(node)
        return node  # int, float, bool, datetime pass through unchanged

    @staticmethod
    def _mask_email(match: re.Match) -> str:
        """a***@domain.com — domain preserved for mail-routing debugging."""
        parts = match.group(0).split("@", 1)
        return f"{parts[0][0]}***@{parts[1]}"

    @staticmethod
    def _luhn(number: str) -> bool:
        """Luhn checksum — prevents masking random numeric sequences as card numbers."""
        digits = [int(d) for d in number if d.isdigit()]
        doubled = [d * 2 - 9 if d * 2 > 9 else d * 2 for d in digits[-2::-2]]
        return (sum(digits[-1::-2]) + sum(doubled)) % 10 == 0

    def _maybe_mask_card(self, match: re.Match) -> str:
        raw        = match.group(0)
        digits     = re.sub(r"\D", "", raw)
        if len(digits) >= 13 and self._luhn(digits):
            return f"****{digits[-4:]}"  # ****1234 — last 4 digits for support lookups
        return raw  # not a valid card number; leave untouched

    def _dlp_mask(self, text: str) -> str:
        """
        Cloud DLP deidentify call with 2 s timeout.
        Falls back silently on any error — the regex path still runs after this.
        Timeout is intentionally short: DLP is an enhancement, not a hard dependency.
        """
        try:
            item = {"value": text}
            inspect_config = {
                "info_types": [
                    {"name": "EMAIL_ADDRESS"},
                    {"name": "PHONE_NUMBER"},
                    {"name": "CREDIT_CARD_NUMBER"},
                    {"name": "IBAN_CODE"},
                ],
                "min_likelihood": "LIKELY",
            }
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [{
                        "primitive_transformation": {"replace_with_info_type_config": {}}
                    }]
                }
            }
            resp = _dlp_client.deidentify_content(
                request={
                    "parent": f"projects/{GCP_PROJECT}",
                    "deidentify_config": deidentify_config,
                    "inspect_config": inspect_config,
                    "item": item,
                },
                timeout=2.0,
            )
            return resp.item.value
        except Exception as exc:
            logger.debug("DLP call failed, using regex fallback: %s", exc)
            return text


# Module-level singleton — import this object everywhere, never instantiate DataMasker directly.
masker = DataMasker()
