from typing import Optional

from pydantic import BaseModel, Field


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
