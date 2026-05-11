import httpx
from fastapi import HTTPException
from google.auth import default as gauth_default
from google.auth.transport.requests import Request as GAuthRequest

from config import GCP_PROJECT, GCP_LOCATION, MA_TEMPLATE_ID
from logging_utils import log, log_error

_credentials, _ = gauth_default()


async def armor_sanitize(text: str, suffix: str) -> str:
    """
    Call Model Armor sanitization endpoint.
    - suffix = "sanitizeUserPrompt"    for inputs
    - suffix = "sanitizeModelResponse" for outputs

    Masking always runs before this call — Model Armor sees already-masked text.
    Fail-open on errors so an armor outage does not take down the agent.
    """
    if not MA_TEMPLATE_ID:
        return text

    url = (
        f"https://modelarmor.googleapis.com/v1"
        f"/projects/{GCP_PROJECT}/locations/{GCP_LOCATION}"
        f"/templates/{MA_TEMPLATE_ID}:{suffix}"
    )
    _credentials.refresh(GAuthRequest())
    headers = {
        "Authorization": f"Bearer {_credentials.token}",
        "Content-Type": "application/json",
    }
    payload = (
        {"userPromptData":     {"text": text}} if "Prompt" in suffix
        else {"modelResponseData": {"text": text}}
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            log_error("armor_http_error", Exception(str(resp.status_code)))
            return text

        verdict = resp.json().get("sanitizationResult", {}).get("filterMatchState", "")
        if verdict == "MATCH_FOUND":
            log("armor_blocked", suffix=suffix)
            raise HTTPException(status_code=400, detail="Request could not be processed.")
    except HTTPException:
        raise
    except Exception as exc:
        log_error("armor_exception", exc)

    return text
