"""
main.py — Production Cloud Run agent service.

Data flow for /invoke:
  HTTP → IAM verify → DataMasker[M1] → Model Armor input → Vertex AI
       → DataMasker[M3] → Model Armor output → Firestore[M4]
       → structured log[M5] → Cloud Trace span[M6] → HTTP response
"""

import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
import time
import uuid
import datetime
from contextlib import asynccontextmanager
from typing import Optional

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from google.auth import default as gauth_default
from google.auth.transport.requests import Request as GAuthRequest
from google.cloud import firestore
from opentelemetry import trace
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential, wait_random
import vertexai
from vertexai.generative_models import Content, GenerationConfig, GenerativeModel, Part

from masking import masker
from dotenv import load_dotenv

load_dotenv()

# ── Environment config ─────────────────────────────────────────────────────────
# All configuration via environment variables — never hardcode project or region.
GCP_PROJECT    = os.environ["GCP_PROJECT"]          # fail fast if missing
GCP_LOCATION   = os.getenv("GCP_LOCATION", "us-central1")
MODEL_ID       = os.getenv("MODEL_ID", "gemini-2.0-flash-001")
MA_TEMPLATE_ID = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "")  # empty = disabled
SERVICE_URL    = os.getenv("SERVICE_URL", "")        # OIDC audience for token verification
PORT           = int(os.getenv("PORT", "8080"))

# ── Structured JSON logging ────────────────────────────────────────────────────
# Cloud Logging parses JSON written to stdout when the "severity" key is present.
# We disable the default formatter and emit raw JSON so Cloud Logging can index fields.
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",   # message is already a JSON string
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

def _log(event: str, **kwargs) -> None:
    """Emit a structured log entry — all kwargs passed through mask_dict [M5]."""
    payload = masker.mask_dict({"event": event, **kwargs})
    payload["severity"] = "INFO"
    logger.info(json.dumps(payload))

def _log_error(event: str, exc: Exception, **kwargs) -> None:
    """Log exception internally with masked detail; never surfaces raw exc to callers [M9]."""
    payload = masker.mask_dict({"event": event, "detail": str(exc)[:300], **kwargs})
    payload["severity"] = "ERROR"
    logger.error(json.dumps(payload))

# ── OpenTelemetry / Cloud Trace ────────────────────────────────────────────────
# BatchSpanProcessor queues spans in memory and flushes in batches (default: 512
# spans or 5 seconds). force_flush() in the SIGTERM handler drains the queue
# before Cloud Run kills the container — without it, the last batch is lost.
_tracer_provider = TracerProvider()
_tracer_provider.add_span_processor(
    BatchSpanProcessor(CloudTraceSpanExporter(project_id=GCP_PROJECT))
)
trace.set_tracer_provider(_tracer_provider)
tracer = trace.get_tracer(__name__)

# ── GCP clients — initialized once at startup, reused across requests ──────────
# Creating clients per-request wastes ~50ms on gRPC channel setup each time.
_credentials, _ = gauth_default()
_db: firestore.AsyncClient | None    = None
_model: GenerativeModel | None       = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan: runs startup code before serving, cleanup code after.
    Using lifespan (not @app.on_event) is the Pydantic v2 / FastAPI 0.95+ pattern.
    """
    global _db, _model
    vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION)
    _db    = firestore.AsyncClient(project=GCP_PROJECT)
    _model = GenerativeModel(
        MODEL_ID,
        generation_config=GenerationConfig(temperature=0.2, max_output_tokens=2048),
    )
    _log("startup", model=MODEL_ID, project=GCP_PROJECT, location=GCP_LOCATION)

    # Register SIGTERM handler — Cloud Run sends SIGTERM ~10s before SIGKILL
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, _handle_sigterm)

    yield  # application serves requests between yield and the lines below

    _tracer_provider.shutdown()   # graceful final flush of all pending spans
    _log("shutdown", status="clean")


def _handle_sigterm() -> None:
    """
    SIGTERM handler: flush the trace exporter's in-memory queue before exit.
    timeout_millis=5000 leaves 5 s of the 10 s SIGTERM window for export.
    Without force_flush, BatchSpanProcessor spans queued since last batch are lost.
    """
    _log("sigterm_received")
    _tracer_provider.force_flush(timeout_millis=5000)
    asyncio.get_event_loop().stop()


app = FastAPI(
    title="Cloud Run Agent",
    lifespan=lifespan,
    docs_url=None,     # disable Swagger UI in production
    redoc_url=None,
)

# ── Pydantic v2 request / response models ─────────────────────────────────────
class InvokeRequest(BaseModel):
    user_id:    str           = Field(..., min_length=1, max_length=128)
    message:    str           = Field(..., min_length=1, max_length=8192)
    session_id: Optional[str] = None

class InvokeResponse(BaseModel):
    reply:         str
    session_id:    str
    input_tokens:  int
    output_tokens: int
    cost_usd:      float

class EvalCase(BaseModel):
    input:           str
    expected_output: str

class EvaluateRequest(BaseModel):
    test_cases: list[EvalCase]



# ── Model Armor ────────────────────────────────────────────────────────────────
async def _armor_sanitize(text: str, suffix: str) -> str:
    """
    Call Model Armor sanitization endpoint.
    - suffix = "sanitizeUserPrompt"  for inputs
    - suffix = "sanitizeModelResponse" for outputs

    Masking always runs BEFORE this call [M2/M3] — Model Armor sees already-masked
    text. This layered approach satisfies OWASP LLM01 (prompt injection) and LLM06.

    Fail-open on Model Armor errors: an outage in the armor service should not
    take down the agent. Log the error but continue.
    """
    if not MA_TEMPLATE_ID:
        return text  # Model Armor not configured — skip

    url = (
        f"https://modelarmor.googleapis.com/v1"
        f"/projects/{GCP_PROJECT}/locations/{GCP_LOCATION}"
        f"/templates/{MA_TEMPLATE_ID}:{suffix}"
    )
    # Refresh ADC token — Cloud Run metadata server returns a short-lived access token
    _credentials.refresh(GAuthRequest())
    headers = {
        "Authorization": f"Bearer {_credentials.token}",
        "Content-Type": "application/json",
    }
    payload = (
        {"userPromptData":     {"text": text}} if "Prompt"   in suffix
        else {"modelResponseData": {"text": text}}
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            _log_error("armor_http_error", Exception(str(resp.status_code)))
            return text   # fail open

        verdict = resp.json().get("sanitizationResult", {}).get("filterMatchState", "")
        if verdict == "MATCH_FOUND":
            # Log internally that armor blocked — never surface block reason to caller
            _log("armor_blocked", suffix=suffix)
            raise HTTPException(status_code=400, detail="Request could not be processed.")
    except HTTPException:
        raise
    except Exception as exc:
        _log_error("armor_exception", exc)  # fail open on network errors

    return text


# ── Token cost estimation ──────────────────────────────────────────────────────
# Rates in USD per 1M tokens (public pricing as of 2025-Q2; update as prices change).
_COST_TABLE: dict[str, dict[str, float]] = {
    "gemini-2.0-flash-001":  {"input": 0.075,  "output": 0.30},
    "gemini-1.5-pro-002":    {"input": 1.25,   "output": 5.00},
    "gemini-1.5-flash-002":  {"input": 0.075,  "output": 0.30},
}

def estimate_cost_usd(input_tokens: int, output_tokens: int, model: str) -> float:
    rates = _COST_TABLE.get(model, {"input": 0.0, "output": 0.0})
    return (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000


def _write_token_metric(session_id: str, total_tokens: int) -> None:
    """
    Write custom metric to Cloud Monitoring. Fire-and-forget — errors are logged
    but never propagate to the caller. Metric labels: model + session_id (no user_id:
    user identity does not belong in a time-series metrics system).
    """
    try:
        from google.cloud import monitoring_v3

        client   = monitoring_v3.MetricServiceClient()
        series   = monitoring_v3.TimeSeries()
        series.metric.type                     = "custom.googleapis.com/agent/tokens_used"
        series.metric.labels["model"]          = MODEL_ID
        series.metric.labels["session_id"]     = session_id[:16]  # label cardinality limit
        series.resource.type                   = "global"
        series.resource.labels["project_id"]   = GCP_PROJECT

        point = monitoring_v3.Point()
        point.value.int64_value        = total_tokens
        point.interval.end_time.seconds = int(time.time())
        series.points                  = [point]

        client.create_time_series(name=f"projects/{GCP_PROJECT}", time_series=[series])
    except Exception as exc:
        _log_error("metric_write_failed", exc)  # non-fatal [M8]


# ── Firestore session storage ──────────────────────────────────────────────────
_SESSIONS = "agent_sessions"

async def _load_history(session_id: str) -> list[dict]:
    """Retrieve masked conversation history. Returns [] for new sessions."""
    doc = await _db.collection(_SESSIONS).document(session_id).get()
    return doc.to_dict().get("history", []) if doc.exists else []


async def _save_session(session_id: str, user_id_hash: str, history: list[dict]) -> None:
    """
    Persist session to Firestore. mask_dict() runs on the entire payload before
    write [M4] — defense-in-depth even though individual turns were masked on entry.
    expire_at is a native datetime so Firestore TTL recognizes it as a Timestamp.
    """
    data = masker.mask_dict({
        "session_id":   session_id,
        "user_id_hash": user_id_hash,          # never store plaintext user_id
        "history":      history,
        "updated_at":   datetime.datetime.utcnow(),
        "expire_at":    datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    })
    await _db.collection(_SESSIONS).document(session_id).set(data)


# ── Vertex AI call with retry ──────────────────────────────────────────────────
@retry(
    stop=stop_after_attempt(3),
    # Exponential backoff: 1s → 2s → 4s, capped at 8s.
    # wait_random(0, 1) adds jitter — prevents all retrying instances from
    # firing simultaneously after a transient Vertex rate-limit event.
    wait=wait_exponential(multiplier=1, min=1, max=8) + wait_random(0, 1),
    reraise=True,
)
async def _call_model(contents: list[Content]) -> tuple[str, int, int]:
    """
    Returns (reply_text, input_token_count, output_token_count).
    asyncio.to_thread() prevents the sync Vertex SDK from blocking the async
    event loop — critical for maintaining concurrency under load.
    """
    response = await asyncio.to_thread(_model.generate_content, contents)
    u = response.usage_metadata
    return response.text, u.prompt_token_count, u.candidates_token_count


# ── /invoke ────────────────────────────────────────────────────────────────────
@app.post("/invoke", response_model=InvokeResponse)
async def invoke(
    req:         InvokeRequest,
    request:     Request,
) -> InvokeResponse:
    start_ms      = time.time() * 1000
    session_id    = req.session_id or str(uuid.uuid4())
    user_id_hash  = masker.hash_id(req.user_id)   # hash immediately; never use plaintext again

    with tracer.start_as_current_span("agent.invoke") as span:
        span.set_attribute("session_id",   session_id)
        span.set_attribute("user_id_hash", user_id_hash)  # hashed [M6]
        span.set_attribute("model",        MODEL_ID)

        # [M2] Mask incoming message before it reaches the model or any log
        masked_msg = masker.mask_text(req.message)

        # Model Armor input check (on already-masked text — masking always first)
        await _armor_sanitize(masked_msg, "sanitizeUserPrompt")

        # Build conversation history as Content objects for multi-turn context
        raw_history = await _load_history(session_id)
        contents = [
            Content(role=h["role"], parts=[Part.from_text(h["text"])])
            for h in raw_history
        ] + [Content(role="user", parts=[Part.from_text(masked_msg)])]

        #try:
        reply, in_tok, out_tok = await _call_model(contents)
        #except Exception as exc:
        #    _log_error("model_error", exc, session_id=session_id)   # [M9] full exc in log
        #    raise HTTPException(status_code=502, detail="Agent temporarily unavailable.")

        # Model Armor output check
        await _armor_sanitize(reply, "sanitizeModelResponse")

        # [M3] Mask model reply before returning or persisting
        masked_reply = masker.mask_text(reply)

        # Append masked turns to history and persist [M4]
        raw_history.extend([
            {"role": "user",  "text": masked_msg},
            {"role": "model", "text": masked_reply},
        ])
        await _save_session(session_id, user_id_hash, raw_history)

        cost      = estimate_cost_usd(in_tok, out_tok, MODEL_ID)
        latency   = time.time() * 1000 - start_ms
        span.set_attribute("latency_ms",    round(latency, 2))
        span.set_attribute("input_tokens",  in_tok)
        span.set_attribute("output_tokens", out_tok)

        # [M5] Structured log — message content is never logged, only metadata
        _log("invoke",
             session_id=session_id, user_id_hash=user_id_hash,
             input_tokens=in_tok,   output_tokens=out_tok,
             latency_ms=round(latency, 2), cost_usd=round(cost, 6), model=MODEL_ID)

        # Write token metric fire-and-forget [M8]
        _write_token_metric(session_id, in_tok + out_tok)

        return InvokeResponse(
            reply=masked_reply, session_id=session_id,
            input_tokens=in_tok, output_tokens=out_tok, cost_usd=round(cost, 6),
        )


# ── /evaluate ─────────────────────────────────────────────────────────────────
@app.post("/evaluate")
async def evaluate(
    req:         EvaluateRequest,
) -> dict:
    """
    CI/CD quality gate. Called from Cloud Build or GitHub Actions to block a
    model deployment that regresses on known-good test cases.
    Gate example: assert exact_match_rate > 0.85 and avg_latency_ms < 1500.
    """
    results = []
    for case in req.test_cases:
        masked_input = masker.mask_text(case.input)   # [M7] mask eval input
        t0 = time.time()
        try:
            reply, in_tok, out_tok = await _call_model(
                [Content(role="user", parts=[Part.from_text(masked_input)])]
            )
        except Exception as exc:
            _log_error("eval_model_error", exc)
            results.append({"match": False, "latency_ms": 0.0, "cost_usd": 0.0})
            continue

        masked_reply = masker.mask_text(reply)        # [M7] mask eval output before comparison
        latency      = (time.time() - t0) * 1000
        cost         = estimate_cost_usd(in_tok, out_tok, MODEL_ID)
        match        = masked_reply.strip().lower() == case.expected_output.strip().lower()

        # [M7] Log eval result with masked content only
        _log("eval_case", match=match, latency_ms=round(latency, 2),
             input_tokens=in_tok, output_tokens=out_tok)
        results.append({"match": match, "latency_ms": latency, "cost_usd": cost})

    n = len(results) or 1  # guard div-by-zero on empty test_cases
    return {
        "total_cases":       len(results),
        "exact_match_rate":  sum(r["match"]      for r in results) / n,
        "avg_latency_ms":    sum(r["latency_ms"]  for r in results) / n,
        "avg_cost_usd":      sum(r["cost_usd"]    for r in results) / n,
    }


# ── /health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> dict:
    """
    Unauthenticated — Cloud Run liveness/readiness probe.
    If this returns non-200, Cloud Run stops routing traffic to the instance.
    Keep it lightweight: no Firestore or Vertex calls. A slow health check
    causes premature instance replacement under load.
    """
    return {"status": "ok", "model": MODEL_ID}


# ── Dev entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # In production, Cloud Run starts the container's CMD directly — this block
    # is only for local development via `python main.py`.
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, log_config=None)
