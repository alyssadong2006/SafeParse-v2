"""SafeParse FastAPI application."""
import logging

from fastapi import FastAPI

from config import settings
from app.api.v1.endpoints import router

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Render and sanitize untrusted web content before LLM ingestion.",
)
app.include_router(router, prefix=settings.api_prefix, tags=["sanitization"])


@app.get("/health", tags=["operations"])
async def health():
    return {"status": "ok"}
