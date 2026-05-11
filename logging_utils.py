import json
import logging
import sys

from masking import masker

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
_logger = logging.getLogger(__name__)


def log(event: str, **kwargs) -> None:
    payload = masker.mask_dict({"event": event, **kwargs})
    payload["severity"] = "INFO"
    _logger.info(json.dumps(payload))


def log_error(event: str, exc: Exception, **kwargs) -> None:
    payload = masker.mask_dict({"event": event, "detail": str(exc)[:300], **kwargs})
    payload["severity"] = "ERROR"
    _logger.error(json.dumps(payload))
