"""FastAPI routes for vm-ai-debugger."""
import asyncio
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from backend.agents.investigator import investigate
from backend.db.database import (
    save_investigation, update_investigation,
    mark_investigation_error, get_investigation,
    list_investigations, save_feedback
)

logger = logging.getLogger(__name__)
router = APIRouter()


class InvestigateRequest(BaseModel):
    site_name: str = Field(default="", description="IIS site name to inspect")
    app_path: str = Field(default="", description="Physical path to the .NET app")
    check_mysql: bool = Field(default=True, description="Include database inspection")
    check_network: bool = Field(default=True, description="Include network checks")
    target_host: str = Field(default="", description="Hostname/IP to check connectivity to")


class FeedbackRequest(BaseModel):
    helpful: bool
    comment: Optional[str] = None


async def _run_investigation(inv_id: str, req: InvestigateRequest):
    try:
        result = await asyncio.to_thread(
            investigate,
            site_name=req.site_name,
            app_path=req.app_path,
            check_mysql=req.check_mysql,
            check_network=req.check_network,
            target_host=req.target_host,
        )
        update_investigation(inv_id, result)
        logger.info("Investigation %s completed: category=%s",
                    inv_id, result.get("analysis", {}).get("failure_category"))
    except Exception as e:
        logger.exception("Investigation %s failed", inv_id)
        mark_investigation_error(inv_id, str(e))


@router.post("/investigate", status_code=202)
async def start_investigation(req: InvestigateRequest, background_tasks: BackgroundTasks):
    inv_id = save_investigation(
        namespace=req.site_name or "vm",
        pod_name=None, deployment_name=None,
        node_name=None, job_name=None, scan_mode="full",
    )
    background_tasks.add_task(_run_investigation, inv_id, req)
    return {"investigation_id": inv_id, "status": "running",
            "message": "Investigation started. Poll /investigation/{id} for results."}


@router.post("/investigate/sync")
async def investigate_sync(req: InvestigateRequest):
    inv_id = save_investigation(
        namespace=req.site_name or "vm",
        pod_name=None, deployment_name=None,
        node_name=None, job_name=None, scan_mode="full",
    )
    try:
        result = await asyncio.to_thread(
            investigate,
            site_name=req.site_name,
            app_path=req.app_path,
            check_mysql=req.check_mysql,
            check_network=req.check_network,
            target_host=req.target_host,
        )
        update_investigation(inv_id, result)
        return {"investigation_id": inv_id, "status": "completed", **result}
    except Exception as e:
        mark_investigation_error(inv_id, str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/investigation/{inv_id}")
async def get_investigation_result(inv_id: str):
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/history")
async def get_history(limit: int = 50):
    return {"investigations": list_investigations(limit=min(limit, 200))}


@router.post("/investigation/{inv_id}/feedback")
async def submit_feedback(inv_id: str, req: FeedbackRequest):
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    fb_id = save_feedback(inv_id, req.helpful, req.comment)
    return {"feedback_id": fb_id}


@router.get("/health")
async def health():
    import os
    from backend.tools.winrm_connector import is_windows_configured
    from backend.tools.ssh_connector import is_linux_configured
    from backend.tools.database_inspector import get_configured_databases

    configured_dbs = get_configured_databases()
    db_summary = {}
    for db in configured_dbs:
        db_summary[db["type"]] = {
            "host": db["host"],
            "databases": db.get("databases", []),
        }

    return {
        "status": "ok",
        "service": "vm-ai-debugger",
        "connections": {
            "windows_vm": {
                "configured": is_windows_configured(),
                "host": os.getenv("VM_WINDOWS_HOST", ""),
            },
            "linux_vm": {
                "configured": is_linux_configured(),
                "host": os.getenv("VM_LINUX_HOST", ""),
            },
        },
        "databases": db_summary,
        "llm_providers": {
            "anthropic": bool(os.getenv("ANTHROPIC_API_KEY", "")),
            "openrouter": bool(os.getenv("OPENROUTER_API_KEY", "")),
            "gemini": bool(os.getenv("GEMINI_API_KEY", "")),
        },
    }