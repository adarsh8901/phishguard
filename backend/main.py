"""Local PhishGuard API.

The service intentionally exposes only the endpoints used by the extension.
"""

from datetime import datetime, timezone
import json
import logging
import time
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path
from threading import RLock

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

try:
    from .engine import analyze_url, normalize_url
    from .ai_model import predict_with_ai
except ImportError:
    from engine import analyze_url, normalize_url
    from ai_model import predict_with_ai


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("phishguard")

app = FastAPI(title="PhishGuard Local API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex=r"^(chrome-extension://.*|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

STATE_FILE = Path(__file__).resolve().parent / "data" / "db.json"
HISTORY_LIMIT = 50
HISTORY_DEDUP_WINDOW_SECONDS = 30
STATE_LOCK = RLock()
scan_history: list[dict] = []


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)
    use_network: bool = True


def load_history() -> None:
    """Load scan history while tolerating legacy state and damaged files."""
    with STATE_LOCK:
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            rows = data.get("scans", []) if isinstance(data, dict) else []
            scan_history[:] = rows[:HISTORY_LIMIT] if isinstance(rows, list) else []
        except FileNotFoundError:
            LOGGER.info("No scan history found; starting with an empty history")
        except (OSError, json.JSONDecodeError) as error:
            LOGGER.warning("Could not load scan history: %s", error)


def save_history() -> None:
    with STATE_LOCK:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(
                json.dumps({"scans": scan_history[:HISTORY_LIMIT]}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            LOGGER.exception("Could not persist scan history")


def record_scan(result: dict) -> None:
    try:
        normalized_url = normalize_url(result.get("url", ""))
    except ValueError:
        normalized_url = result.get("url")
    record = {
        "url": normalized_url,
        "confidence": result.get("confidence"),
        "risk_score": result.get("risk_score"),
        "status": result.get("status"),
        "recommendation": result.get("recommendation"),
        "reasons": result.get("reasons", []),
        "source": result.get("source"),
        "success": result.get("success") is True,
        "error": result.get("error"),
        "scanned_at": result.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
    }
    with STATE_LOCK:
        if scan_history:
            latest = scan_history[0]
            def history_key(value):
                try:
                    parsed = urlsplit(value or "")
                    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
                except (TypeError, ValueError):
                    return value
            try:
                latest_time = datetime.fromisoformat(str(latest.get("scanned_at", "")).replace("Z", "+00:00"))
                current_time = datetime.fromisoformat(record["scanned_at"].replace("Z", "+00:00"))
                recent = abs((current_time - latest_time).total_seconds()) <= HISTORY_DEDUP_WINDOW_SECONDS
            except (TypeError, ValueError):
                recent = False
            same_result = (
                history_key(latest.get("url")) == history_key(record["url"])
                and latest.get("status") == record["status"]
                and latest.get("risk_score") == record["risk_score"]
            )
            if recent and same_result:
                scan_history[0] = record
                save_history()
                return
        scan_history.insert(0, record)
        del scan_history[HISTORY_LIMIT:]
        save_history()


load_history()


@app.post("/predict")
def predict(request: ScanRequest):
    scan_started = time.perf_counter()
    LOGGER.info("Scan requested for URL length=%d", len(request.url))
    try:
        stage_started = time.perf_counter()
        result = analyze_url(request.url, use_network=request.use_network)
        LOGGER.info("Rule/network analysis stage took %.2fs", time.perf_counter() - stage_started)
        if not isinstance(result, dict) or "risk_score" not in result:
            raise RuntimeError("Analyzer returned an incomplete result")
        stage_started = time.perf_counter()
        model_ai = predict_with_ai(result.get("url", request.url), result.get("features", {}))
        LOGGER.info("AI/model inference stage took %.2fs", time.perf_counter() - stage_started)
        raw_score = result.get("risk_score")
        if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            raise RuntimeError("Core URL analysis returned an invalid risk score")
        risk_score = max(0.0, min(float(raw_score), 100.0))
        rule_probability = max(0.0, min(risk_score / 100, 1.0))
        model_probability = (
            float(model_ai["phishing_probability"])
            if model_ai.get("available")
            and isinstance(model_ai.get("phishing_probability"), (int, float))
            else None
        )
        # The URL-text model is supplementary: a confident model guess must be
        # corroborated by URL rules before it can raise the final risk score.
        # This prevents ordinary sites from being labelled Critical solely
        # because their URL happens to resemble training-data text patterns.
        model_corroborated = (
            model_probability is not None
            and model_probability >= 0.85
            and risk_score >= 30
        )
        phishing_probability = max(
            rule_probability,
            model_probability if model_corroborated else 0.0,
        )
        is_phishing = (
            result.get("is_phishing") is True
            or risk_score >= 70
            or model_corroborated
        )

        effective_risk_score = round(phishing_probability * 100)
        result["rule_risk_score"] = risk_score
        result["risk_score"] = effective_risk_score
        result["is_phishing"] = is_phishing
        result["should_block"] = result.get("should_block") is True or is_phishing
        analysis_complete = bool(result.get("analysis_complete"))
        if not analysis_complete:
            raise RuntimeError("Core URL analysis did not complete")
        result["analysis_complete"] = True
        warnings = list(result.get("warnings") or [])
        if not model_ai.get("available"):
            warnings.append("ai_model_unavailable")
        result["warnings"] = list(dict.fromkeys(warnings))
        result["analysis_mode"] = "full" if result.get("analysis_mode") == "full" and model_ai.get("available") else "heuristic_only"
        result["status"] = "dangerous" if is_phishing else "safe"
        result["risk_classification"] = (
            "Critical" if effective_risk_score >= 85
            else "High" if effective_risk_score >= 70
            else "Suspicious" if effective_risk_score >= 40
            else "Safe"
        )
        result["severity"] = result["risk_classification"].lower()
        result["verdict"] = (
            "DANGEROUS" if is_phishing
            else "SUSPICIOUS" if effective_risk_score >= 40
            else "SAFE"
        )

        result["raw_model_analysis"] = model_ai
        result["ai_analysis"] = {
            "available": bool(model_ai.get("available")),
            "prediction": "phishing" if is_phishing else "safe" if analysis_complete else "unknown",
            "confidence": round(max(phishing_probability, 1 - phishing_probability), 4),
            "phishing_probability": round(phishing_probability, 4),
            "safe_probability": round(1 - phishing_probability, 4),
            "model": model_ai.get("model", "final_risk_ensemble") if isinstance(model_ai, dict) else "final_risk_ensemble",
            "model_corroborated": model_corroborated,
            "reason": model_ai.get("reason") if not model_ai.get("available") else None,
            "note": "Final verdict combines URL rules and model output, so the popup never shows contradictory Safe/Phishing results.",
        }
    except ValueError as error:
        LOGGER.info("Rejected scan request for %r: %s", request.url, error)
        return _failure_response(request.url, "invalid_url", 422)
    except Exception:
        LOGGER.exception("URL analysis failed")
        return _failure_response(request.url, "internal_analysis_error", 500)

    response = _success_response(result)
    record_scan(response)
    LOGGER.info("Scanned %s with risk score %s in %s mode in %.2fs", result.get("domain"), response["risk_score"], response["analysis_mode"], time.perf_counter() - scan_started)
    return response


def _success_response(result: dict) -> dict:
    reasons = result.get("blocking_reasons") or [
        item.get("feature", "").replace("_", " ").capitalize()
        for item in result.get("feature_importance", []) if item.get("feature")
    ]
    return {
        "url": result["url"], "status": result["verdict"],
        "risk_score": result["risk_score"],
        "confidence": result.get("confidence_percentage", round(float(result.get("confidence", 0)) * 100)),
        "recommendation": result.get("recommendation", ""), "reasons": reasons,
        "source": "backend", "success": True, "error": None,
        "analysis_mode": result.get("analysis_mode", "heuristic_only"),
        "warnings": result.get("warnings", []),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _failure_response(url: str, error: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={
        "url": url, "status": "UNKNOWN", "risk_score": None, "confidence": 0,
        "recommendation": "Analysis could not be completed.", "reasons": [],
        "source": "backend", "success": False, "error": error,
        "analysis_mode": "heuristic_only", "warnings": [],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    })


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, _error: RequestValidationError):
    return _failure_response(None, "invalid_request", 422)


@app.exception_handler(Exception)
async def unexpected_exception_handler(_request: Request, error: Exception):
    LOGGER.exception("Unhandled API failure", exc_info=error)
    return _failure_response(None, "internal_analysis_error", 500)


@app.get("/health")
def health():
    return {"status": "ok", "service": "phishguard", "version": "1.0"}


@app.get("/history")
def get_history():
    with STATE_LOCK:
        return list(scan_history)


@app.get("/dashboard")
def get_dashboard():
    with STATE_LOCK:
        history = list(scan_history)
    phishing_count = sum(item.get("status") == "DANGEROUS" for item in history)
    return {
        "status": "online",
        "total_scans": len(history),
        "phishing_count": phishing_count,
        "safe_count": len(history) - phishing_count,
        "recent": history[:10],
    }


if __name__ == "__main__":
    app_location = "backend.main:app" if __package__ else "main:app"
    uvicorn.run(app_location, host="127.0.0.1", port=8080, reload=False)
