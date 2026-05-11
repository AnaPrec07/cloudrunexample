import time

from config import GCP_PROJECT, MODEL_ID
from logging_utils import log_error

# Rates in USD per 1M tokens (public pricing as of 2025-Q2).
_COST_TABLE: dict[str, dict[str, float]] = {
    "gemini-2.0-flash-001": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro-002":   {"input": 1.25,  "output": 5.00},
    "gemini-1.5-flash-002": {"input": 0.075, "output": 0.30},
}


def estimate_cost_usd(input_tokens: int, output_tokens: int, model: str) -> float:
    rates = _COST_TABLE.get(model, {"input": 0.0, "output": 0.0})
    return (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000


def write_token_metric(session_id: str, total_tokens: int) -> None:
    """Fire-and-forget — errors are logged but never propagate to the caller."""
    try:
        from google.cloud import monitoring_v3

        client  = monitoring_v3.MetricServiceClient()
        series  = monitoring_v3.TimeSeries()
        series.metric.type                   = "custom.googleapis.com/agent/tokens_used"
        series.metric.labels["model"]        = MODEL_ID
        series.metric.labels["session_id"]   = session_id[:16]
        series.resource.type                 = "global"
        series.resource.labels["project_id"] = GCP_PROJECT

        point = monitoring_v3.Point()
        point.value.int64_value              = total_tokens
        point.interval.end_time.seconds      = int(time.time())
        series.points                        = [point]

        client.create_time_series(name=f"projects/{GCP_PROJECT}", time_series=[series])
    except Exception as exc:
        log_error("metric_write_failed", exc)
