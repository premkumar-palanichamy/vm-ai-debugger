"""vm-ai-debugger — FastAPI application entry point."""
from dotenv import load_dotenv
load_dotenv()

import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.api.routes import router
from backend.db.database import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VM AI Debugger",
    description="AI-powered Windows/Linux VM troubleshooting — IIS, .NET, MySQL, SAML2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
async def startup():
    init_db()
    logger.info("vm-ai-debugger started — DB initialized")


frontend_dir = Path(__file__).parent.parent / "frontend"
if (frontend_dir / "static").exists():
    app.mount("/static", StaticFiles(directory=frontend_dir / "static"), name="static")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    index = frontend_dir / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "VM AI Debugger running. Visit /docs for API reference."}
