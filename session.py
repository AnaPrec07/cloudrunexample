import datetime

from fastapi import HTTPException
from google.cloud import firestore
from masking import masker

from config import GCP_PROJECT, SESSION_TOKEN_BUDGET
from logging_utils import log

_SESSIONS = "agent_sessions"
_db: firestore.AsyncClient | None = None


def init_db() -> None:
    global _db
    _db = firestore.AsyncClient(project=GCP_PROJECT)


async def load_history(session_id: str) -> tuple[list[dict], int]:
    """Return (history, cumulative_token_count); ([], 0) for new sessions."""
    doc = await _db.collection(_SESSIONS).document(session_id).get()
    if doc.exists:
        d = doc.to_dict()
        return d.get("history", []), d.get("total_tokens", 0)
    return [], 0


def check_session_budget(session_id: str, session_tokens: int) -> None:
    if session_tokens >= SESSION_TOKEN_BUDGET:
        log(
            "session_budget_exceeded",
            session_id=session_id,
            session_tokens=session_tokens,
            budget=SESSION_TOKEN_BUDGET,
            why_stopped="budget_exceeded",
        )
        raise HTTPException(
            status_code=429,
            detail="Session token budget exceeded. Start a new session.",
        )


async def save_session(
    session_id: str,
    user_id_hash: str,
    history: list[dict],
    total_tokens: int,
) -> None:
    """Persist session — mask_dict runs on the full payload before write."""
    data = masker.mask_dict({
        "session_id":   session_id,
        "user_id_hash": user_id_hash,
        "history":      history,
        "total_tokens": total_tokens,
        "updated_at":   datetime.datetime.utcnow(),
        "expire_at":    datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    })
    await _db.collection(_SESSIONS).document(session_id).set(data)
