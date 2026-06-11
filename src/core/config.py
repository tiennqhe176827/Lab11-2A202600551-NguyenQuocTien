"""
Lab 11 - Configuration & API Key Setup
"""
import os


ENV_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".env")
)


def load_env_file(path=ENV_PATH):
    """Load simple KEY=VALUE pairs from .env without requiring python-dotenv."""
    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value:
                os.environ[key] = value


load_env_file()


def setup_api_key():
    """Load Google API key from .env or environment or prompt."""
    load_env_file()
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "False")
    print("API key loaded.")


# Gemini model name - set MODEL_NAME in .env to change it for the app.
MODEL_NAME = os.environ.get("MODEL_NAME", "gemini-2.5-flash-lite").strip()
if not MODEL_NAME:
    raise ValueError("MODEL_NAME cannot be empty. Set MODEL_NAME in .env.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
