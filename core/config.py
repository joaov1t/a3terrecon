import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Global config for A3terRecon."""

    USER_AGENT = "A3terRecon/1.0 (+https://github.com/joaov1t/a3terrecon)"
    TIMEOUT = 10
    MAX_RETRIES = 3
    DELAY = 0  # seconds between requests (avoid rate limits)

    # APIs (set via .env or env vars)
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
    CENSYS_UID = os.getenv("CENSYS_UID", "")
    CENSYS_SECRET = os.getenv("CENSYS_SECRET", "")

    # Proxies (optional, e.g. "http://127.0.0.1:8080" for Burp)
    PROXY = os.getenv("A3TERRECON_PROXY", "")

    # Output
    REPORT_DIR = PROJECT_DIR / "reports"

    @classmethod
    def get_proxy_dict(cls):
        if cls.PROXY:
            return {"http": cls.PROXY, "https": cls.PROXY}
        return None
