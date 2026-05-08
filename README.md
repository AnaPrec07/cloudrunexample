# Cloud Run Agent

Production-grade Gemini agent on Cloud Run. IAM-only access. PII masked at all sinks.

## Prerequisites

```bash
gcloud components install beta
gcloud services enable \
  run.googleapis.com \
  aiplatform.googleapis.com \
  firestore.googleapis.com \
  cloudtrace.googleapis.com \
  monitoring.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com \
  --project=wireless-choice
```

Create a Firestore database (native mode) if you don't have one:
```bash
gcloud firestore databases create --location=nam5 --project=wireless-choice
```

## Local Development

```bash
# 1. Authenticate with ADC (uses your user credentials locally)
gcloud auth application-default login

# 2. Configure environment
cp .env.example .env
# Edit .env: set GCP_PROJECT at minimum

# 3. Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Run
python main.py
# Server starts at http://localhost:8080

# 5. Health check
curl http://localhost:8080/health

# 6. Invoke (no auth required locally if SERVICE_URL is empty)
curl -X POST http://localhost:8080/invoke \
  -H "Content-Type: application/json" \
  -d '{"user_id": "local-test", "message": "What is Cloud Run?"}'
```

## Deploy

```bash
bash deploy.sh
```

See the post-deploy steps printed by the script: set Firestore TTL, update SERVICE_URL env var.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/invoke` | IAM required | Send a message, get a reply |
| POST | `/evaluate` | IAM required | Run evaluation test cases |
| GET | `/health` | None | Liveness probe |

## Data flow

```
POST /invoke
  → IAM token verify
  → DataMasker.mask_text(message)          [M2]
  → Model Armor sanitizeUserPrompt
  → Vertex AI (Gemini)
  → Model Armor sanitizeModelResponse
  → DataMasker.mask_text(reply)            [M3]
  → Firestore session write (masked)       [M4]
  → Cloud Trace span (user_id hashed)      [M6]
  → Structured log (no message content)    [M5]
  → HTTP response
```

## Masking points reference

See `masking.py` module docstring for the full list of [M1]–[M9] masking points
and which component is responsible for each.
