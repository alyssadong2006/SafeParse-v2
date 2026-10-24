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
    guardrail_model_enabled = os.getenv("SAFEPARSE_GUARDRAIL_MODEL_ENABLED", "true").lower() == "true"
    guardrail_model_name = os.getenv(
        "SAFEPARSE_GUARDRAIL_MODEL_NAME",
        "deepset/deberta-v3-base-injection",
    )
    guardrail_model_revision = os.getenv(
        "SAFEPARSE_GUARDRAIL_MODEL_REVISION",
        "80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1",
    )
    guardrail_model_max_chunks = int(os.getenv("SAFEPARSE_GUARDRAIL_MODEL_MAX_CHUNKS", "8"))
    guardrail_model_flag_threshold = float(
        os.getenv("SAFEPARSE_GUARDRAIL_MODEL_FLAG_THRESHOLD", "0.5")
    )


settings = Settings()
