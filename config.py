"""Application configuration loaded from environment variables."""
import os


class Settings:
    app_name = "SafeParse"
    api_prefix = "/api/v1"
    default_timeout_seconds = int(os.getenv("SAFEPARSE_DEFAULT_TIMEOUT", "15"))
    max_timeout_seconds = int(os.getenv("SAFEPARSE_MAX_TIMEOUT", "30"))
    max_output_characters = int(os.getenv("SAFEPARSE_MAX_OUTPUT_CHARS", "200000"))
    max_download_bytes = int(os.getenv("SAFEPARSE_MAX_DOWNLOAD_BYTES", "5000000"))
    navigation_max_redirects = int(os.getenv("SAFEPARSE_MAX_REDIRECTS", "10"))
    allow_private_networks = os.getenv("SAFEPARSE_ALLOW_PRIVATE_NETWORKS", "false").lower() == "true"
    threat_threshold = float(os.getenv("SAFEPARSE_THREAT_THRESHOLD", "0.35"))


settings = Settings()
