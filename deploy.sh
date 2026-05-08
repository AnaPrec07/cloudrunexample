#!/usr/bin/env bash
# deploy.sh — Build, push, and deploy the Cloud Run agent.
# Usage: bash deploy.sh
# Prerequisites: gcloud CLI authenticated, Artifact Registry repo created,
#               Firestore database created (native mode).
set -euo pipefail

# ── Load .env for local runs (never committed to git) ─────────────────────────
[[ -f .env ]] && set -o allexport && source .env && set +o allexport

# ── Required variables (fail fast if unset) ───────────────────────────────────
: "${GCP_PROJECT:?Set GCP_PROJECT in .env or environment}"
: "${ARTIFACT_REGISTRY_REPO:?Set ARTIFACT_REGISTRY_REPO (e.g., agent-repo)}"

REGION="${GCP_LOCATION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-cloudrun-agent}"
SA_NAME="${SA_NAME:-cloudrun-agent-sa}"
SA_EMAIL="${SA_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com"
MODEL="${MODEL_ID:-gemini-2.0-flash-001}"
IMAGE="${REGION}-docker.pkg.dev/${GCP_PROJECT}/${ARTIFACT_REGISTRY_REPO}/${SERVICE_NAME}:latest"

echo "▶ Project:  ${GCP_PROJECT}"
echo "▶ Region:   ${REGION}"
echo "▶ Service:  ${SERVICE_NAME}"
echo "▶ SA:       ${SA_EMAIL}"
echo "▶ Image:    ${IMAGE}"

# ── 1. Create service account (idempotent) ────────────────────────────────────
echo "▶ Creating service account..."
gcloud iam service-accounts create "${SA_NAME}" \
  --project="${GCP_PROJECT}" \
  --display-name="Cloud Run Agent SA" 2>/dev/null \
  || echo "  SA already exists — skipping"

# ── 2. Grant least-privilege IAM roles ────────────────────────────────────────
# roles/aiplatform.user — generate_content calls to Vertex AI
# roles/datastore.user  — read/write Firestore documents
# roles/cloudtrace.agent — write trace spans
# roles/monitoring.metricWriter — write custom metrics
# roles/secretmanager.secretAccessor — read Secret Manager secrets at runtime
echo "▶ Granting IAM roles..."
for ROLE in \
    roles/aiplatform.user \
    roles/datastore.user \
    roles/cloudtrace.agent \
    roles/monitoring.metricWriter \
    roles/secretmanager.secretAccessor; do
  gcloud projects add-iam-policy-binding "${GCP_PROJECT}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --quiet
done

# ── 3. Store MODEL_ARMOR_TEMPLATE_ID in Secret Manager ────────────────────────
# Env vars in Cloud Run metadata are visible to run.services.get callers.
# Secret Manager values are only accessible to SAs with secretAccessor role.
if [[ -n "${MODEL_ARMOR_TEMPLATE_ID:-}" ]]; then
  echo "▶ Storing Model Armor template ID in Secret Manager..."
  echo -n "${MODEL_ARMOR_TEMPLATE_ID}" \
    | gcloud secrets create model-armor-template-id \
        --project="${GCP_PROJECT}" --data-file=- 2>/dev/null \
    || echo -n "${MODEL_ARMOR_TEMPLATE_ID}" \
    | gcloud secrets versions add model-armor-template-id \
        --project="${GCP_PROJECT}" --data-file=-
fi

# ── 4. Build image via Cloud Build (Linux x86-64, not local machine arch) ─────
# Building on Cloud Build avoids platform-mismatch issues with C-extension wheels
# (e.g., grpcio built for Darwin arm64 will crash on Cloud Run Linux x86-64).
echo "▶ Building image via Cloud Build..."
gcloud builds submit \
  --tag="${IMAGE}" \
  --project="${GCP_PROJECT}" \
  --timeout=600s

# ── 5. Deploy to Cloud Run ────────────────────────────────────────────────────
echo "▶ Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT} \
  --service-account=${SA_EMAIL} \
  --no-allow-unauthenticated \
  --set-env-vars=GCP_PROJECT=${GCP_PROJECT},GCP_LOCATION=${REGION},MODEL_ID=${MODEL} \
  # --set-secrets=MODEL_ARMOR_TEMPLATE_ID=model-armor-template-id:latest \
  --memory=512Mi \
  --cpu=1 \
  --concurrency=80 \
  --timeout=60 \
  --min-instances=0 \
  --max-instances=10

# ── 6. Capture and export the service URL ────────────────────────────────────
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --region="${REGION}" \
  --project="${GCP_PROJECT}" \
  --format="value(status.url)")

echo ""
echo "✓ Deployed: ${SERVICE_URL}"
echo ""
echo "─── Post-deploy one-time steps ──────────────────────────────────────────"
echo ""
echo "① Enable Firestore TTL on the expire_at field (run once per project):"
echo "   gcloud firestore fields ttls update expire_at \\"
echo "     --collection-group=agent_sessions \\"
echo "     --project=${GCP_PROJECT}"
echo ""
echo "② Store SERVICE_URL so IAM token verification uses the correct audience:"
echo "   gcloud run services update ${SERVICE_NAME} \\"
echo "     --region=${REGION} --project=${GCP_PROJECT} \\"
echo "     --set-env-vars=SERVICE_URL=${SERVICE_URL}"
echo ""
echo "③ Verify health check (unauthenticated):"
echo "   curl ${SERVICE_URL}/health"
echo ""
echo "④ Test authenticated invocation:"
echo "   TOKEN=\$(gcloud auth print-identity-token)"
echo "   curl -H \"Authorization: Bearer \$TOKEN\" \\"
echo "        -H \"Content-Type: application/json\" \\"
echo "        -d '{\"user_id\":\"u1\",\"message\":\"hello\"}' \\"
echo "        ${SERVICE_URL}/invoke"
