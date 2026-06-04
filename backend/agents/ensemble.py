"""
Multi-Model Ensemble Agent

Fully automatic — no toggles or manual config needed.
Just add API keys to .env and the system decides:

  1 key  → investigator.py handles it as single model (this file not called)
  2 keys → runs both in parallel, correlates results
  3 keys → full 3-way correlation, highest confidence

Supported providers (add the key to enable):
  Anthropic  → ANTHROPIC_API_KEY   (claude-sonnet-4-6 by default)
  OpenRouter → OPENROUTER_API_KEY  (configure model via OPENROUTER_MODEL)
  Gemini     → GEMINI_API_KEY      (gemini-1.5-flash by default)
"""
import os
import asyncio
import logging
import json
import httpx
from collections import Counter

logger = logging.getLogger(__name__)

# ── System prompt shared by all models ───────────────────────────────
SYSTEM_PROMPT = """You are an expert Kubernetes SRE. Analyze the given cluster evidence and identify the root cause.

FAILURE CATEGORIES (pick exactly one):
pod_crash, image_pull, scheduling, node_health, storage, rbac, quota,
hpa, job_failure, cert_expiry, networking, rollout, config_error, argocd_sync, unknown

Respond ONLY with valid JSON — no markdown, no explanation outside JSON:
{
  "root_cause": "concise description of root cause",
  "failure_category": "one category from the list above",
  "confidence": 85,
  "severity": "critical|high|medium|low",
  "signals": ["signal 1", "signal 2", "signal 3"],
  "affected_resources": ["pod/name", "deployment/name"],
  "fix_recommendations": [
    {
      "step": 1,
      "description": "what to do",
      "command": "exact kubectl command",
      "expected_outcome": "what success looks like"
    }
  ],
  "prevention": "how to prevent this in future",
  "summary": "2-3 sentence plain English explanation"
}"""


# ── Detect which models are configured ───────────────────────────────
def get_configured_models() -> list[dict]:
    """
    Reads .env and returns only the models that have API keys configured.
    Each entry has: name, provider, api_key, model_id, call_fn
    """
    configured = []

    # 1. Anthropic direct
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if anthropic_key:
        configured.append({
            "name": "claude",
            "label": "Claude (Anthropic)",
            "api_key": anthropic_key,
            "model_id": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            "provider": "anthropic",
        })

    # 2. OpenRouter (can run any model)
    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if openrouter_key:
        configured.append({
            "name": "openrouter",
            "label": f"OpenRouter ({os.getenv('OPENROUTER_MODEL', 'anthropic/claude-3-haiku')})",
            "api_key": openrouter_key,
            "model_id": os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku"),
            "provider": "openrouter",
        })

    # 3. Google Gemini direct
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if gemini_key:
        configured.append({
            "name": "gemini",
            "label": "Gemini (Google)",
            "api_key": gemini_key,
            "model_id": os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            "provider": "gemini",
        })

    logger.info(
        "Configured models: %s",
        [m["label"] for m in configured] or ["none"]
    )
    return configured


# ── Model callers ─────────────────────────────────────────────────────
async def _call_anthropic(model: dict, evidence_text: str, system_prompt: str = "") -> dict:
    """Call Claude directly via Anthropic SDK (run in thread — SDK is sync)."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=model["api_key"])

        def _sync_call():
            return client.messages.create(
                model=model["model_id"],
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": f"Analyze this Kubernetes evidence:\n\n{evidence_text}"
                }],
            )

        response = await asyncio.to_thread(_sync_call)
        content = response.content[0].text
        parsed = _parse_response(content)
        parsed.update({"model": model["name"], "label": model["label"],
                       "model_id": model["model_id"], "status": "success"})
        logger.info("Claude responded: category=%s confidence=%s",
                    parsed.get("failure_category"), parsed.get("confidence"))
        return parsed

    except Exception as e:
        logger.warning("Claude failed: %s", e)
        return _error_result(model, str(e))


async def _call_openrouter(model: dict, evidence_text: str, system_prompt: str = "") -> dict:
    """Call any model via OpenRouter API."""
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {model['api_key']}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/premkumar-palanichamy/k8s-ai-debugger",
                    "X-Title": "K8s AI Debugger",
                },
                json={
                    "model": model["model_id"],
                    "temperature": 0.1,
                    "max_tokens": 1500,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze this Kubernetes evidence:\n\n{evidence_text}"},
                    ],
                },
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            parsed = _parse_response(content)
            parsed.update({"model": model["name"], "label": model["label"],
                           "model_id": model["model_id"], "status": "success"})
            logger.info("OpenRouter (%s) responded: category=%s confidence=%s",
                        model["model_id"], parsed.get("failure_category"), parsed.get("confidence"))
            return parsed

    except Exception as e:
        logger.warning("OpenRouter failed: %s", e)
        return _error_result(model, str(e))


async def _call_gemini(model: dict, evidence_text: str, system_prompt: str = "") -> dict:
    """Call Gemini directly via Google AI API."""
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model['model_id']}:generateContent",
                params={"key": model["api_key"]},
                headers={"Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                    "contents": [{
                        "parts": [{"text": f"Analyze this Kubernetes evidence:\n\n{evidence_text}"}]
                    }],
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


# ── Route to correct caller based on provider ────────────────────────
async def _call_model(model: dict, evidence_text: str, system_prompt: str = "") -> dict:
    if model["provider"] == "anthropic":
        return await _call_anthropic(model, evidence_text, system_prompt)
    elif model["provider"] == "openrouter":
        return await _call_openrouter(model, evidence_text, system_prompt)
    elif model["provider"] == "gemini":
        return await _call_gemini(model, evidence_text, system_prompt)
    else:
        return _error_result(model, f"Unknown provider: {model['provider']}")


# ── Correlation logic ─────────────────────────────────────────────────
def _correlate(results: list[dict], total_configured: int) -> dict:
    """
    Compare results from all models that responded successfully.

    Correlation rules:
      1 model  → no ensemble, just that model's result
      2 models, both agree  → HIGH
      2 models, disagree    → LOW
      3+ models, all agree  → HIGH
      3+ models, majority   → MEDIUM
      3+ models, all differ → LOW
    """
    successful = [r for r in results if r.get("status") == "success"]
    failed = [r for r in results if r.get("status") == "error"]

    if not successful:
        return {
            "correlation": "FAILED",
            "agreed_category": "unknown",
            "ensemble_confidence": 0,
            "recommendation": "All models failed. Check your API keys.",
            "needs_human_review": True,
        }

    # Only 1 model responded or configured — no correlation needed
    if len(successful) == 1:
        r = successful[0]
        return {
            "correlation": "SINGLE",
            "agreed_category": r.get("failure_category", "unknown"),
            "ensemble_confidence": r.get("confidence", 0),
            "severity": r.get("severity", "unknown"),
            "recommendation": f"Only {r['label']} was configured or responded. Add more API keys to enable ensemble correlation.",
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

    # Multiple models — do correlation
    categories = [r["failure_category"] for r in successful if r.get("failure_category")]
    confidences = [r["confidence"] for r in successful if r.get("confidence")]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    category_counts = Counter(categories)
    most_common_category, most_common_count = category_counts.most_common(1)[0] if category_counts else ("unknown", 0)
    total = len(successful)

    if most_common_count == total:
        correlation = "HIGH"
        confidence_boost = 20
        recommendation = f"All {total} models agree — diagnosis is highly reliable."
        needs_review = False
    elif most_common_count >= 2:
        correlation = "MEDIUM"
        confidence_boost = 10
        agreeing = [r["label"] for r in successful if r.get("failure_category") == most_common_category]
        disagreeing = [r["label"] for r in successful if r.get("failure_category") != most_common_category]
        recommendation = f"{', '.join(agreeing)} agree. {', '.join(disagreeing)} differ — review signals carefully."
        needs_review = False
    else:
        correlation = "LOW"
        confidence_boost = -20
        recommendation = "Models disagree on root cause — human review recommended."
        needs_review = True

    ensemble_confidence = min(100, max(0, round(avg_confidence + confidence_boost)))

    # Best result = most confident among agreeing models
    agreeing_results = [r for r in successful if r.get("failure_category") == most_common_category]
    best_result = max(agreeing_results, key=lambda r: r.get("confidence", 0))

    # Severity — highest among agreeing models
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_severity = max(
        [r.get("severity", "low") for r in agreeing_results],
        key=lambda s: severity_rank.get(s, 0)
    )

    # Merge signals (deduplicated)
    seen, merged_signals = set(), []
    for r in agreeing_results:
        for s in r.get("signals", []):
            if s not in seen:
                seen.add(s)
                merged_signals.append(s)

    return {
        "correlation": correlation,
        "agreed_category": most_common_category,
        "ensemble_confidence": ensemble_confidence,
        "severity": top_severity,
        "recommendation": recommendation,
        "needs_human_review": needs_review,
        "merged_signals": merged_signals[:10],
        "fix_recommendations": best_result.get("fix_recommendations", []),
        "prevention": best_result.get("prevention", ""),
        "summary": best_result.get("summary", ""),
        "affected_resources": best_result.get("affected_resources", []),
        "category_votes": dict(category_counts),
        "model_count": total,
        "successful_models": [r["label"] for r in successful],
        "failed_models": [r["label"] for r in failed],
    }


# ── Helpers ───────────────────────────────────────────────────────────
def _parse_response(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    if content.startswith("json"):
        content = content[4:].strip()
    return json.loads(content)


def _error_result(model: dict, error: str) -> dict:
    return {
        "model": model["name"],
        "label": model["label"],
        "model_id": model["model_id"],
        "status": "error",
        "error": error,
        "failure_category": None,
        "confidence": 0,
    }


# ── Main ensemble entry point ─────────────────────────────────────────
async def analyze_with_ensemble(evidence: dict, system_prompt: str = "") -> dict:
    """
    Dynamically detects configured models from .env,
    runs them all in parallel, and correlates results.
    Uses dynamic system_prompt built from detected services.
    """
    from backend.tools.service_detector import build_system_prompt
    if not system_prompt:
        detected = evidence.get("detected_services", {})
        system_prompt = build_system_prompt(detected)

    configured = get_configured_models()

    if not configured:
        return {
            "ensemble": "not_configured",
            "error": "No API keys found. Set ANTHROPIC_API_KEY, OPENROUTER_API_KEY, or GEMINI_API_KEY in .env",
        }

    # Truncate evidence if too large
    evidence_text = json.dumps(evidence, indent=2, default=str)
    if len(evidence_text) > 60000:
        logger.warning("Evidence too large, truncating for ensemble")
        if "logs" in evidence:
            evidence["logs"]["current"] = evidence["logs"]["current"][-2000:]
            evidence["logs"]["previous"] = None
        evidence_text = json.dumps(evidence, indent=2, default=str)

    logger.info("Running ensemble with %d model(s): %s",
                len(configured), [m["label"] for m in configured])

    # Run all configured models in PARALLEL
    tasks = [_call_model(model, evidence_text, system_prompt) for model in configured]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    correlation = _correlate(list(results), len(configured))

    return {
        "models": {r["model"]: r for r in results},
        "correlation": correlation,
        "configured_count": len(configured),
    }


# ── Sync wrapper ──────────────────────────────────────────────────────
def analyze_with_ensemble_sync(evidence: dict, system_prompt: str = "") -> dict:
    """Synchronous wrapper — called from investigator.py."""
    return asyncio.run(analyze_with_ensemble(evidence, system_prompt))
