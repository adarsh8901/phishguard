"""Optional local ML inference for PhishGuard.

The legacy model was saved without feature-name metadata. Keep the feature order
centralized here so inference is deterministic and easy to replace when a model
with embedded metadata is trained.
"""

import logging
import time
from pathlib import Path
from threading import Lock

LOGGER = logging.getLogger("phishguard.ai")
MODEL_PATH = Path(__file__).resolve().parent / "models" / "phish_model.joblib"
LEGACY_MODEL_PATH = (
    Path(__file__).resolve().parents[1] / "extension" / "full_package"
    / "backend" / "models" / "phish_model.joblib"
)

# Feature order retained only for compatibility with the legacy Random Forest.
FEATURE_NAMES = (
    "url_length",
    "num_special_chars",
    "num_digits",
    "has_ip",
    "num_subdomains",
    "path_depth",
    "has_suspicious_tld",
    "has_login_keywords",
    "domain_length",
    "is_url_shortener",
    "domain_age_days",
    "has_https",
    "dns_resolved",
    "ssl_valid",
    "query_param_count",
)

_model = None
_load_attempted = False
_load_error = None
_model_lock = Lock()


def _load_model():
    global _model, _load_attempted, _load_error
    if _load_attempted and _model is not None:
        return _model

    with _model_lock:
        if _load_attempted:
            return _model
        started = time.perf_counter()
        try:
            import joblib

            selected_path = MODEL_PATH if MODEL_PATH.exists() else LEGACY_MODEL_PATH
            artifact = joblib.load(selected_path)
            candidate = artifact.get("model") if isinstance(artifact, dict) else artifact
            if not hasattr(candidate, "predict_proba"):
                raise TypeError("model does not support probability predictions")
            expected = getattr(candidate, "n_features_in_", len(FEATURE_NAMES))
            if not hasattr(candidate, "named_steps") and expected != len(FEATURE_NAMES):
                raise ValueError(f"model expects {expected} features, not {len(FEATURE_NAMES)}")
            metadata = artifact.get("meta", {}) if isinstance(artifact, dict) else {}
            stored_features = metadata.get("feature_names")
            if stored_features and tuple(stored_features) != FEATURE_NAMES:
                raise ValueError("model feature order does not match the inference feature order")
            _model = candidate
            LOGGER.info("Loaded local AI model from %s", selected_path)
        except Exception as error:
            _load_error = str(error)
            LOGGER.warning("Local AI model unavailable: %s", error)
        finally:
            # Publish completion only after the model or load error is ready.
            # Concurrent first requests block on the lock instead of observing
            # a transient, unexplained unavailable state.
            _load_attempted = True
            LOGGER.info("AI model load stage took %.2fs", time.perf_counter() - started)
        return _model


def _feature_vector(features: dict) -> list[float]:
    ssl_data = features.get("ssl") or {}
    values = dict(features)
    values["ssl_valid"] = int(bool(ssl_data.get("valid")))
    return [float(values.get(name, 0) or 0) for name in FEATURE_NAMES]


def predict_with_ai(url: str, features: dict) -> dict:
    """Return a supplementary model result without altering rule scoring."""
    model = _load_model()
    if model is None:
        return {
            "available": False,
            "prediction": "unavailable",
            "confidence": None,
            "reason": _load_error or "Model could not be loaded",
        }

    started = time.perf_counter()
    try:
        model_input = [url.lower()] if hasattr(model, "named_steps") else [_feature_vector(features)]
        probabilities = model.predict_proba(model_input)[0]
        classes = list(model.classes_)
        phishing_index = classes.index(1) if 1 in classes else len(probabilities) - 1
        phishing_probability = float(probabilities[phishing_index])
        result = {
            "available": True,
            "prediction": "phishing" if phishing_probability >= 0.5 else "safe",
            "confidence": round(
                phishing_probability if phishing_probability >= 0.5 else 1 - phishing_probability,
                4,
            ),
            "phishing_probability": round(phishing_probability, 4),
            "model": "url_text_classifier" if hasattr(model, "named_steps") else "random_forest",
        }
        LOGGER.info("AI inference took %.2fs", time.perf_counter() - started)
        return result
    except Exception as error:
        LOGGER.warning("Local AI inference failed: %s", error)
        return {
            "available": False,
            "prediction": "unavailable",
            "confidence": None,
            "reason": str(error),
        }
