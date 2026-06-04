"""
VM Investigation Agent — gathers evidence from Windows/Linux VMs,
analyzes with single model or multi-model ensemble automatically.
"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone

from backend.tools.winrm_connector import WinRMConnector, is_windows_configured
from backend.tools.ssh_connector import SSHConnector, is_linux_configured
from backend.tools.system_inspector import inspect_windows_system, inspect_linux_system
from backend.tools.iis_inspector import inspect_iis
from backend.tools.dotnet_inspector import inspect_dotnet_app
from backend.tools.windows_events import inspect_windows_events
from backend.tools.database_inspector import inspect_all_databases, get_configured_databases
from backend.tools.network_inspector import inspect_vm_network, inspect_network_via_winrm
from backend.tools.service_detector import detect_windows_services, detect_linux_services, build_system_prompt

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) specializing in:
- Windows Server administration and IIS web server
- ASP.NET Core application troubleshooting
- SAML2 / SSO authentication issues
- MySQL database performance and connectivity
- Linux server administration
- Network connectivity, SSL certificates, firewall rules

You are given evidence from a VM investigation. Analyze ALL evidence holistically.

FAILURE CATEGORIES (pick exactly one):
- iis_failure: IIS app pool stopped, W3SVC down, site not started
- dotnet_crash: ASP.NET Core app crash, unhandled exception, startup failure
- saml2_error: SAML2 metadata missing/invalid, SSO configuration error
- mysql_down: MySQL service stopped, connection refused, auth failed
- mysql_performance: slow queries, too many connections, buffer pool full
- high_cpu: CPU usage critical, runaway process
- high_memory: memory exhaustion, OOM kill
- disk_full: disk space critical on OS or data drive
- ssl_expiry: SSL certificate expired or expiring soon
- network_blocked: port blocked, firewall rule, DNS failure
- service_crashed: Windows service stopped unexpectedly
- config_error: appsettings.json misconfigured, missing env vars
- pending_reboot: Windows update pending restart causing instability
- unknown: cannot determine root cause

Respond ONLY with valid JSON:
{
  "root_cause": "max 8 words — short title e.g. Disk full on E drive",
  "failure_category": "one category from above",
  "confidence": 85,
  "severity": "critical|high|medium|low",
  "signals": ["signal 1", "signal 2"],
  "affected_resources": ["IIS/SiteName", "Service/MySQL"],
  "fix_recommendations": [
    {
      "step": 1,
      "description": "what to do",
      "command": "exact PowerShell or bash command",
      "expected_outcome": "what success looks like"
    }
  ],
  "prevention": "how to prevent this",
  "summary": "2-3 sentence plain English explanation"
}"""


def gather_evidence(
    site_name: str = "",
    app_path: str = "",
    check_mysql: bool = True,
    check_network: bool = True,
    target_host: str = "",
) -> dict:
    """Collect evidence from all configured VM tools."""
    evidence = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "site_name": site_name,
        "vm_type": [],
    }

    # ── Windows VM ──────────────────────────────────────────────────
    if is_windows_configured():
        evidence["vm_type"].append("windows")
        win_conn = None
        try:
            win_conn = WinRMConnector()
            win_conn.connect()
            logger.info("Connected to Windows VM — collecting evidence")

            # Auto-detect what's running — used to build dynamic LLM prompt
            evidence["detected_services"] = detect_windows_services(win_conn)

            evidence["system"] = inspect_windows_system(win_conn)
            evidence["iis"] = inspect_iis(win_conn)
            evidence["dotnet"] = inspect_dotnet_app(win_conn, site_name=site_name, app_path=app_path)
            evidence["events"] = inspect_windows_events(win_conn)

            # Database inspection — done while WinRM connection is still open
            if check_mysql:
                try:
                    evidence["databases"] = inspect_all_databases(winrm_conn=win_conn)
                except Exception as e:
                    evidence["database_error"] = str(e)

            # Network from inside VM
            if check_network:
                evidence["network_internal"] = inspect_network_via_winrm(win_conn, target_host=target_host)

        except Exception as e:
            logger.error("Windows VM evidence collection failed: %s", e)
            evidence["windows_error"] = str(e)
        finally:
            if win_conn:
                win_conn.disconnect()

    # ── Linux VM ───────────────────────────────────────────────────
    if is_linux_configured():
        evidence["vm_type"].append("linux")
        linux_conn = None
        try:
            linux_conn = SSHConnector()
            linux_conn.connect()
            logger.info("Connected to Linux VM — collecting evidence")
            evidence["detected_services"] = detect_linux_services(linux_conn)
            evidence["system_linux"] = inspect_linux_system(linux_conn)
        except Exception as e:
            logger.error("Linux VM evidence collection failed: %s", e)
            evidence["linux_error"] = str(e)
        finally:
            if linux_conn:
                linux_conn.disconnect()

    # ── External network checks ────────────────────────────────────
    if check_network and target_host:
        evidence["network_external"] = inspect_vm_network(target_host)

    return evidence


def analyze_with_llm(evidence: dict, dynamic_prompt: str = "") -> dict:
    """Send evidence to configured LLM — auto-detects provider."""
    evidence_text = json.dumps(evidence, indent=2, default=str)
    if len(evidence_text) > 80000:
        evidence_text = evidence_text[:80000] + "\n... [truncated]"

    user_message = f"""Investigate this VM evidence and identify the root cause:

<evidence>
{evidence_text}
</evidence>

Respond with valid JSON only."""

    # Try providers in order
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if anthropic_key:
        return _call_anthropic(user_message, anthropic_key, dynamic_prompt)

    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if openrouter_key:
        return _call_openrouter(user_message, openrouter_key, dynamic_prompt)

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if gemini_key:
        return _call_gemini(user_message, gemini_key, dynamic_prompt)

    raise ValueError("No API key configured. Set ANTHROPIC_API_KEY, OPENROUTER_API_KEY, or GEMINI_API_KEY in .env")


def _call_anthropic(user_message: str, api_key: str, system_prompt: str = "") -> dict:
    import anthropic
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model, max_tokens=2048,
        system=system_prompt or SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return _parse_response(message.content[0].text)


def _call_openrouter(user_message: str, api_key: str, system_prompt: str = "") -> dict:
    import httpx
    model = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
    response = httpx.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                 "HTTP-Referer": "https://github.com/premkumar-palanichamy/vm-ai-debugger"},
        json={"model": model, "messages": [{"role": "system", "content": system_prompt or SYSTEM_PROMPT},
                                            {"role": "user", "content": user_message}], "temperature": 0.1},
        timeout=90,
    )
    response.raise_for_status()
    return _parse_response(response.json()["choices"][0]["message"]["content"])


def _call_gemini(user_message: str, api_key: str, system_prompt: str = "") -> dict:
    import httpx
    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    response = httpx.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        params={"key": api_key},
        headers={"Content-Type": "application/json"},
        json={"system_instruction": {"parts": [{"text": system_prompt or SYSTEM_PROMPT}]},
              "contents": [{"parts": [{"text": user_message}]}],
              "generationConfig": {"temperature": 0.1, "maxOutputTokens": 2048}},
        timeout=90,
    )
    response.raise_for_status()
    return _parse_response(response.json()["candidates"][0]["content"]["parts"][0]["text"])


def _parse_response(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    if content.startswith("json"):
        content = content[4:].strip()
    return json.loads(content)


def investigate(
    site_name: str = "",
    app_path: str = "",
    check_mysql: bool = True,
    check_network: bool = True,
    target_host: str = "",
) -> dict:
    """Main entry point — gather evidence and analyze."""
    logger.info("Starting VM investigation: site=%s mysql=%s network=%s", site_name, check_mysql, check_network)

    evidence = gather_evidence(
        site_name=site_name,
        app_path=app_path,
        check_mysql=check_mysql,
        check_network=check_network,
        target_host=target_host,
    )

    # Build dynamic prompt based on detected services on this VM
    detected = evidence.get("detected_services", {})
    dynamic_prompt = build_system_prompt(detected)

    # Auto-detect ensemble vs single model
    from backend.agents.ensemble import get_configured_models, analyze_with_ensemble_sync
    configured = get_configured_models()

    if len(configured) > 1:
        logger.info("Auto-detected %d API keys — running ensemble", len(configured))
        ensemble_result = analyze_with_ensemble_sync(evidence, dynamic_prompt)
        correlation = ensemble_result.get("correlation", {})
        analysis = {
            "root_cause": correlation.get("summary", ""),
            "failure_category": correlation.get("agreed_category", "unknown"),
            "confidence": correlation.get("ensemble_confidence", 0),
            "severity": correlation.get("severity", "unknown"),
            "signals": correlation.get("merged_signals", []),
            "affected_resources": correlation.get("affected_resources", []),
            "fix_recommendations": correlation.get("fix_recommendations", []),
            "prevention": correlation.get("prevention", ""),
            "summary": correlation.get("summary", ""),
            "correlation": correlation.get("correlation", ""),
            "needs_human_review": correlation.get("needs_human_review", False),
        }
        return {
            "site_name": site_name,
            "mode": "ensemble",
            "models_used": [m["label"] for m in configured],
            "evidence": evidence,
            "analysis": analysis,
            "ensemble": ensemble_result,
        }
    else:
        analysis = analyze_with_llm(evidence, dynamic_prompt)
        return {
            "site_name": site_name,
            "mode": "single",
            "models_used": [m["label"] for m in configured] if configured else [],
            "evidence": evidence,
            "analysis": analysis,
        }
