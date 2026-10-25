"""SafeParse FastAPI application."""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from app.api.v1.endpoints import router
from app.engine.renderer import close_renderer, start_renderer

# Take any logs above INFO level and send them to the console.
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await start_renderer()
    try:
        yield
    finally:
        await close_renderer()


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Render and sanitize untrusted web content before LLM ingestion.",
    lifespan=lifespan,
)
app.include_router(router, prefix=settings.api_prefix, tags=["sanitization"])

static_directory = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_directory), name="static")


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(static_directory / "index.html")


@app.get("/health", tags=["operations"])
async def health():
    return {"status": "ok"}
