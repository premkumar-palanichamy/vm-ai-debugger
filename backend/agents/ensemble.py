"""
Multi-Model Ensemble Agent — VM AI Debugger

Fully automatic — no toggles needed.
Just add API keys to .env and the system decides:
  1 key  → investigator.py handles as single model
  2 keys → runs both in parallel, correlates results
  3 keys → full 3-way correlation, highest confidence

Uses dynamic system prompt built from detected services on the VM.
"""
import os
import asyncio
import logging
import json
import httpx
from collections import Counter

logger = logging.getLogger(__name__)

# Fallback prompt — only used if service detection fails
SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) specializing in Windows and Linux VM troubleshooting.
This is NOT Kubernetes. Analyze the VM evidence and identify the root cause.
FAILURE CATEGORIES: iis_failure, dotnet_crash, saml2_error, mysql_down, mysql_performance,
high_cpu, high_memory, disk_full, ssl_expiry, network_blocked, service_crashed,
config_error, pending_reboot, unknown
Respond ONLY with valid JSON."""


def get_configured_models() -> list[dict]:
    """Reads .env and returns only models that have API keys configured."""
    configured = []

    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if anthropic_key:
        configured.append({
            "name": "claude", "label": "Claude (Anthropic)",
            "api_key": anthropic_key,
            "model_id": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            "provider": "anthropic",
        })

    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if openrouter_key:
        configured.append({
            "name": "openrouter",
            "label": f"OpenRouter ({os.getenv('OPENROUTER_MODEL', 'anthropic/claude-3-haiku')})",
            "api_key": openrouter_key,
            "model_id": os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku"),
            "provider": "openrouter",
        })

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if gemini_key:
        configured.append({
            "name": "gemini", "label": "Gemini (Google)",
            "api_key": gemini_key,
            "model_id": os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            "provider": "gemini",
        })

    logger.info("Configured models: %s", [m["label"] for m in configured] or ["none"])
    return configured


async def _call_anthropic(model: dict, evidence_text: str, system_prompt: str) -> dict:
    """Call Claude via Anthropic SDK."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=model["api_key"])

        def _sync_call():
            return client.messages.create(
                model=model["model_id"],
                max_tokens=1500,
                system=system_prompt,
                messages=[{"role": "user", "content": f"Analyze this VM evidence:\n\n{evidence_text}"}],
            )

        response = await asyncio.to_thread(_sync_call)
        parsed = _parse_response(response.content[0].text)
        parsed.update({"model": model["name"], "label": model["label"],
                       "model_id": model["model_id"], "status": "success"})
        logger.info("Claude responded: category=%s confidence=%s",
                    parsed.get("failure_category"), parsed.get("confidence"))
        return parsed
    except Exception as e:
        logger.warning("Claude failed: %s", e)
        return _error_result(model, str(e))


async def _call_openrouter(model: dict, evidence_text: str, system_prompt: str) -> dict:
    """Call any model via OpenRouter API."""
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {model['api_key']}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/premkumar-palanichamy/vm-ai-debugger",
                    "X-Title": "VM AI Debugger",
                },
                json={
                    "model": model["model_id"],
                    "temperature": 0.1,
                    "max_tokens": 1500,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Analyze this VM evidence:\n\n{evidence_text}"},
                    ],
                },
            )
            response.raise_for_status()
            parsed = _parse_response(response.json()["choices"][0]["message"]["content"])
            parsed.update({"model": model["name"], "label": model["label"],
                           "model_id": model["model_id"], "status": "success"})
            logger.info("OpenRouter responded: category=%s confidence=%s",
                        parsed.get("failure_category"), parsed.get("confidence"))
            return parsed
    except Exception as e:
        logger.warning("OpenRouter failed: %s", e)
        return _error_result(model, str(e))


async def _call_gemini(model: dict, evidence_text: str, system_prompt: str) -> dict:
    """Call Gemini via Google AI API."""
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model['model_id']}:generateContent",
                params={"key": model["api_key"]},
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"parts": [{"text": f"Analyze this VM evidence:\n\n{evidence_text}"}]}],
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1500},
                },
            )
            response.raise_for_status()
            content = response.json()["candidates"][0]["content"]["parts"][0]["text"]
            parsed = _parse_response(content)
            parsed.update({"model": model["name"], "label": model["label"],
                           "model_id": model["model_id"], "status": "success"})
            logger.info("Gemini responded: category=%s confidence=%s",
                        parsed.get("failure_category"), parsed.get("confidence"))
            return parsed
    except Exception as e:
        logger.warning("Gemini failed: %s", e)
        return _error_result(model, str(e))


async def _call_model(model: dict, evidence_text: str, system_prompt: str) -> dict:
    if model["provider"] == "anthropic":
        return await _call_anthropic(model, evidence_text, system_prompt)
    elif model["provider"] == "openrouter":
        return await _call_openrouter(model, evidence_text, system_prompt)
    elif model["provider"] == "gemini":
        return await _call_gemini(model, evidence_text, system_prompt)
    return _error_result(model, f"Unknown provider: {model['provider']}")


def _correlate(results: list[dict], total_configured: int) -> dict:
    successful = [r for r in results if r.get("status") == "success"]
    failed = [r for r in results if r.get("status") == "error"]

    if not successful:
        return {"correlation": "FAILED", "agreed_category": "unknown",
                "ensemble_confidence": 0, "needs_human_review": True,
                "recommendation": "All models failed. Check your API keys."}

    if len(successful) == 1:
        r = successful[0]
        return {
            "correlation": "SINGLE",
            "agreed_category": r.get("failure_category", "unknown"),
            "ensemble_confidence": r.get("confidence", 0),
            "severity": r.get("severity", "unknown"),
            "recommendation": f"Only {r['label']} responded. Add more API keys for ensemble.",
            "needs_human_review": False,
            "merged_signals": r.get("signals", []),
            "fix_recommendations": r.get("fix_recommendations", []),
            "prevention": r.get("prevention", ""),
            "summary": r.get("summary", ""),
            "affected_resources": r.get("affected_resources", []),
            "category_votes": {r.get("failure_category", "unknown"): 1},
            "model_count": 1,
            "successful_models": [r["label"]],
            "failed_models": [r["label"] for r in failed],
        }

    categories = [r["failure_category"] for r in successful if r.get("failure_category")]
    confidences = [r["confidence"] for r in successful if r.get("confidence")]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    category_counts = Counter(categories)
    most_common, most_count = category_counts.most_common(1)[0] if category_counts else ("unknown", 0)
    total = len(successful)

    if most_count == total:
        correlation, boost = "HIGH", 20
        recommendation = f"All {total} models agree — highly reliable."
        needs_review = False
    elif most_count >= 2:
        correlation, boost = "MEDIUM", 10
        agreeing = [r["label"] for r in successful if r.get("failure_category") == most_common]
        disagreeing = [r["label"] for r in successful if r.get("failure_category") != most_common]
        recommendation = f"{', '.join(agreeing)} agree. {', '.join(disagreeing)} differ."
        needs_review = False
    else:
        correlation, boost = "LOW", -20
        recommendation = "Models disagree — human review recommended."
        needs_review = True

    ensemble_confidence = min(100, max(0, round(avg_confidence + boost)))
    agreeing_results = [r for r in successful if r.get("failure_category") == most_common]
    best = max(agreeing_results, key=lambda r: r.get("confidence", 0))
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_severity = max([r.get("severity", "low") for r in agreeing_results],
                       key=lambda s: severity_rank.get(s, 0))
    seen, merged = set(), []
    for r in agreeing_results:
        for s in r.get("signals", []):
            if s not in seen:
                seen.add(s)
                merged.append(s)

    return {
        "correlation": correlation,
        "agreed_category": most_common,
        "ensemble_confidence": ensemble_confidence,
        "severity": top_severity,
        "recommendation": recommendation,
        "needs_human_review": needs_review,
        "merged_signals": merged[:10],
        "fix_recommendations": best.get("fix_recommendations", []),
        "prevention": best.get("prevention", ""),
        "summary": best.get("summary", ""),
        "affected_resources": best.get("affected_resources", []),
        "category_votes": dict(category_counts),
        "model_count": total,
        "successful_models": [r["label"] for r in successful],
        "failed_models": [r["label"] for r in failed],
    }


def _parse_response(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    if content.startswith("json"):
        content = content[4:].strip()
    return json.loads(content)


def _error_result(model: dict, error: str) -> dict:
    return {"model": model["name"], "label": model["label"], "model_id": model["model_id"],
            "status": "error", "error": error, "failure_category": None, "confidence": 0}


async def analyze_with_ensemble(evidence: dict, system_prompt: str = "") -> dict:
    """Run all configured models in parallel and correlate results."""
    from backend.tools.service_detector import build_system_prompt as build_prompt
    if not system_prompt:
        detected = evidence.get("detected_services", {})
        system_prompt = build_prompt(detected)

    configured = get_configured_models()
    if not configured:
        return {"ensemble": "not_configured",
                "error": "No API keys. Set ANTHROPIC_API_KEY, OPENROUTER_API_KEY, or GEMINI_API_KEY"}

    evidence_text = json.dumps(evidence, indent=2, default=str)
    if len(evidence_text) > 60000:
        logger.warning("Evidence too large, truncating")
        evidence_text = evidence_text[:60000] + "\n...[truncated]"

    logger.info("Running ensemble with %d model(s): %s",
                len(configured), [m["label"] for m in configured])

    tasks = [_call_model(model, evidence_text, system_prompt) for model in configured]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    correlation = _correlate(list(results), len(configured))

    return {"models": {r["model"]: r for r in results},
            "correlation": correlation, "configured_count": len(configured)}


def analyze_with_ensemble_sync(evidence: dict, system_prompt: str = "") -> dict:
    """Synchronous wrapper — called from investigator.py."""
    return asyncio.run(analyze_with_ensemble(evidence, system_prompt))
