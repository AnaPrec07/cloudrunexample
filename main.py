"""
main.py — FastAPI entry point and route definitions.

Data flow for /invoke:
  HTTP → DataMasker[M1] → Model Armor input → Vertex AI
       → DataMasker[M3] → Model Armor output → Firestore[M4]
       → structured log[M5] → Cloud Trace span[M6] → HTTP response
"""

import asyncio
import datetime
import hashlib
import signal
import time
import uuid
from contextlib import asynccontextmanager

import uvicorn
import vertexai
from fastapi import FastAPI, HTTPException, Request
from masking import masker
from vertexai.generative_models import Content, Part

import tracing
import session as session_store
from armor import armor_sanitize
from config import GCP_PROJECT, GCP_LOCATION, MODEL_ID, PORT
from costs import estimate_cost_usd, write_token_metric
from logging_utils import log, log_error
from model import call_model, init_model
from schemas import EvaluateRequest, InvokeRequest, InvokeResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    vertexai.init(project=GCP_PROJECT, location=GCP_LOCATION)
    session_store.init_db()
    init_model()
    log("startup", model=MODEL_ID, project=GCP_PROJECT, location=GCP_LOCATION)

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, _handle_sigterm)

    yield

    tracing.shutdown()
    log("shutdown", status="clean")


def _handle_sigterm() -> None:
    log("sigterm_received")
    tracing.force_flush(timeout_millis=5000)
    asyncio.get_event_loop().stop()


app = FastAPI(
    title="Cloud Run Agent",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)


@app.post("/invoke", response_model=InvokeResponse)
async def invoke(req: InvokeRequest, request: Request) -> InvokeResponse:
    start_ms     = time.time() * 1000
    session_id   = req.session_id or str(uuid.uuid4())
    user_id_hash = masker.hash_id(req.user_id)

    with tracing.tracer.start_as_current_span("agent.invoke") as span:
        span.set_attribute("session_id",   session_id)
        span.set_attribute("user_id_hash", user_id_hash)
        span.set_attribute("model",        MODEL_ID)

        masked_msg = masker.mask_text(req.message)
        await armor_sanitize(masked_msg, "sanitizeUserPrompt")

        raw_history, session_tokens = await session_store.load_history(session_id)
        session_store.check_session_budget(session_id, session_tokens)

        contents = [
            Content(role=h["role"], parts=[Part.from_text(h["text"])])
            for h in raw_history
        ] + [Content(role="user", parts=[Part.from_text(masked_msg)])]

        try:
            reply, in_tok, out_tok = await call_model(contents)
        except Exception as exc:
            log_error("model_error", exc, session_id=session_id)
            raise HTTPException(status_code=502, detail="Agent temporarily unavailable.")

        await armor_sanitize(reply, "sanitizeModelResponse")
        masked_reply = masker.mask_text(reply)

        now_iso = datetime.datetime.utcnow().isoformat()
        raw_history.extend([
            {"role": "user",  "text": masked_msg,   "hash": hashlib.sha256(masked_msg.encode()).hexdigest()[:8],   "ts": now_iso},
            {"role": "model", "text": masked_reply, "hash": hashlib.sha256(masked_reply.encode()).hexdigest()[:8], "ts": now_iso},
        ])
        await session_store.save_session(session_id, user_id_hash, raw_history, session_tokens + in_tok + out_tok)

        cost    = estimate_cost_usd(in_tok, out_tok, MODEL_ID)
        latency = time.time() * 1000 - start_ms
        span.set_attribute("latency_ms",    round(latency, 2))
        span.set_attribute("input_tokens",  in_tok)
        span.set_attribute("output_tokens", out_tok)

        log("invoke",
            session_id=session_id, user_id_hash=user_id_hash,
            input_tokens=in_tok,   output_tokens=out_tok,
            latency_ms=round(latency, 2), cost_usd=round(cost, 6), model=MODEL_ID)

        write_token_metric(session_id, in_tok + out_tok)

        return InvokeResponse(
            reply=masked_reply, session_id=session_id,
            input_tokens=in_tok, output_tokens=out_tok, cost_usd=round(cost, 6),
        )


@app.post("/evaluate")
async def evaluate(req: EvaluateRequest) -> dict:
    """CI/CD quality gate — called from Cloud Build or GitHub Actions."""
    results = []
    for case in req.test_cases:
        masked_input = masker.mask_text(case.input)
        t0 = time.time()
        try:
            reply, in_tok, out_tok = await call_model(
                [Content(role="user", parts=[Part.from_text(masked_input)])]
            )
        except Exception as exc:
            log_error("eval_model_error", exc)
            results.append({"match": False, "latency_ms": 0.0, "cost_usd": 0.0})
            continue

        masked_reply = masker.mask_text(reply)
        latency      = (time.time() - t0) * 1000
        cost         = estimate_cost_usd(in_tok, out_tok, MODEL_ID)
        match        = masked_reply.strip().lower() == case.expected_output.strip().lower()

        log("eval_case", match=match, latency_ms=round(latency, 2),
            input_tokens=in_tok, output_tokens=out_tok)
        results.append({"match": match, "latency_ms": latency, "cost_usd": cost})

    n = len(results) or 1
    return {
        "total_cases":      len(results),
        "exact_match_rate": sum(r["match"]      for r in results) / n,
        "avg_latency_ms":   sum(r["latency_ms"] for r in results) / n,
        "avg_cost_usd":     sum(r["cost_usd"]   for r in results) / n,
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "model": MODEL_ID}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, log_config=None)
