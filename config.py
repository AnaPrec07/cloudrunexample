import os

from dotenv import load_dotenv

load_dotenv()

GCP_PROJECT          = os.environ["GCP_PROJECT"]
GCP_LOCATION         = os.getenv("GCP_LOCATION", "us-central1")
MODEL_ID             = os.getenv("MODEL_ID", "gemini-2.0-flash-001")
MA_TEMPLATE_ID       = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "")
SERVICE_URL          = os.getenv("SERVICE_URL", "")
PORT                 = int(os.getenv("PORT", "8080"))
SESSION_TOKEN_BUDGET = int(os.getenv("SESSION_TOKEN_BUDGET", "20000"))
