import asyncio

from tenacity import retry, stop_after_attempt, wait_exponential, wait_random
from vertexai.generative_models import Content, GenerationConfig, GenerativeModel

from config import MODEL_ID

_model: GenerativeModel | None = None


def init_model() -> None:
    global _model
    _model = GenerativeModel(
        MODEL_ID,
        generation_config=GenerationConfig(temperature=0.2, max_output_tokens=2048),
    )


@retry(
    stop=stop_after_attempt(3),
    # Exponential backoff 1s → 2s → 4s, capped at 8s. wait_random adds jitter
    # to prevent thundering-herd retries after a transient Vertex rate-limit event.
    wait=wait_exponential(multiplier=1, min=1, max=8) + wait_random(0, 1),
    reraise=True,
)
async def call_model(contents: list[Content]) -> tuple[str, int, int]:
    """Return (reply_text, input_token_count, output_token_count)."""
    response = await asyncio.to_thread(_model.generate_content, contents)
    u = response.usage_metadata
    return response.text, u.prompt_token_count, u.candidates_token_count
