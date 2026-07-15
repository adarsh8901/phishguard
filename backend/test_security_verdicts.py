import json

from backend import main
from backend.engine import analyze_url, normalize_url


def complete_result(url="https://example.test"):
    return {
        "url": url,
        "domain": "example.test",
        "risk_score": 0,
        "risk_classification": "Safe",
        "is_phishing": False,
        "should_block": False,
        "analysis_complete": True,
        "verdict": "SAFE",
        "features": {},
        "source": "unit-test",
    }


def response_body(response):
    return json.loads(response.body) if hasattr(response, "body") else response


def test_analyzer_exception_is_http_error_not_safe(monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("analyzer failed")

    monkeypatch.setattr(main, "analyze_url", fail)
    response = main.predict(main.ScanRequest(url="https://example.test"))
    assert response.status_code == 500
    assert response_body(response)["error"] == "internal_analysis_error"


def test_model_unavailable_returns_heuristic_result(monkeypatch):
    monkeypatch.setattr(main, "analyze_url", lambda *_args, **_kwargs: complete_result())
    monkeypatch.setattr(main, "predict_with_ai", lambda *_args, **_kwargs: {
        "available": False, "prediction": "unavailable", "reason": "missing model"
    })
    response = main.predict(main.ScanRequest(url="https://example.test"))
    result = response_body(response)
    assert result["status"] == "SAFE"
    assert result["success"] is True
    assert result["analysis_mode"] == "heuristic_only"
    assert "ai_model_unavailable" in result["warnings"]


def test_brand_impersonation_with_numeric_suffix_is_dangerous():
    result = analyze_url("https://allegrolokainie.pl-95439032.cyou/", use_network=False)
    assert result["risk_score"] == 77
    assert result["verdict"] == "DANGEROUS"
    assert result["analysis_mode"] == "heuristic_only"
    names = {item["feature"] for item in result["feature_importance"]}
    assert "brand_impersonation" in names
    assert "suspicious_numeric_suffix" in names


def test_legitimate_completed_analysis_is_safe(monkeypatch):
    monkeypatch.setattr(main, "analyze_url", lambda *_a, **_k: complete_result("https://www.hotstar.com/"))
    monkeypatch.setattr(main, "predict_with_ai", lambda *_a, **_k: {
        "available": True, "phishing_probability": .03, "model": "test"
    })
    result = main.predict(main.ScanRequest(url="https://www.hotstar.com/"))
    assert result["status"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["success"] is True


def test_completed_maximum_risk_is_dangerous(monkeypatch):
    dangerous = complete_result("https://danger.test/")
    dangerous.update({"risk_score": 100, "is_phishing": True, "should_block": True})
    monkeypatch.setattr(main, "analyze_url", lambda *_a, **_k: dangerous)
    monkeypatch.setattr(main, "predict_with_ai", lambda *_a, **_k: {
        "available": True, "phishing_probability": 1.0, "model": "test"
    })
    result = main.predict(main.ScanRequest(url="https://danger.test/"))
    assert result["status"] == "DANGEROUS"
    assert result["risk_score"] == 100
    assert result["success"] is True


def test_health_contract_is_lightweight():
    assert main.health() == {"status": "ok", "service": "phishguard", "version": "1.0"}


def test_recent_identical_history_entry_is_updated_not_duplicated():
    main.scan_history.clear()
    result = {
        "url": "https://example.test/path#first", "status": "SAFE", "risk_score": 0,
        "confidence": 99, "recommendation": "ok", "reasons": [], "source": "backend",
        "success": True, "error": None, "scanned_at": "2026-07-13T10:00:00+00:00",
    }
    main.record_scan(result)
    result["url"] = "https://example.test/path#second"
    result["scanned_at"] = "2026-07-13T10:00:10+00:00"
    main.record_scan(result)
    assert len(main.scan_history) == 1
    assert main.scan_history[0]["url"] == "https://example.test/path#second"


def test_null_score_is_canonical_unknown(monkeypatch):
    incomplete = complete_result()
    incomplete["risk_score"] = None
    monkeypatch.setattr(main, "analyze_url", lambda *_a, **_k: incomplete)
    monkeypatch.setattr(main, "predict_with_ai", lambda *_a, **_k: {"available": True})
    response = main.predict(main.ScanRequest(url="https://example.test"))
    result = response_body(response)
    assert response.status_code == 500
    assert result["status"] == "UNKNOWN"
    assert result["risk_score"] is None
    assert result["success"] is False


def test_string_unknown_is_not_truthy_phishing(monkeypatch):
    incomplete = complete_result()
    incomplete["is_phishing"] = "unknown"
    incomplete["analysis_complete"] = False
    monkeypatch.setattr(main, "analyze_url", lambda *_a, **_k: incomplete)
    monkeypatch.setattr(main, "predict_with_ai", lambda *_a, **_k: {"available": True})
    response = main.predict(main.ScanRequest(url="https://example.test"))
    result = response_body(response)
    assert response.status_code == 500
    assert result["status"] == "UNKNOWN"
    assert result["success"] is False


def test_history_keeps_unknown_score_null(monkeypatch):
    main.scan_history.clear()
    incomplete = complete_result()
    incomplete.update({"analysis_complete": False, "risk_score": 91})
    monkeypatch.setattr(main, "analyze_url", lambda *_a, **_k: incomplete)
    monkeypatch.setattr(main, "predict_with_ai", lambda *_a, **_k: {"available": False, "reason": "timeout"})
    response = main.predict(main.ScanRequest(url="https://www.hotstar.com/"))
    assert response.status_code == 500
    assert main.scan_history == []


def test_new_domain_and_bad_ssl_score_highly():
    from backend.engine import calculate_risk
    features = {
        "num_domain_digits": 0, "has_ip": 0, "num_subdomains": 0,
        "has_suspicious_tld": 0, "is_url_shortener": 0, "domain_age_days": 2,
        "dns_checked": 1, "dns_resolved": 1, "blacklist_status": "not_listed",
        "brand_impersonation": ["allegro"], "misleading_domain_structure": 1,
        "suspicious_numeric_suffix": 0, "suspicious_domain_keywords": [],
        "homograph_attack": 0, "path_depth": 0, "has_suspicious_path": 0,
        "has_login_keywords": 0, "domain_length": 20, "has_dangerous_extension": 0,
        "many_path_segments": 0, "scheme": "https", "ssl_checked": 1,
        "ssl": {"valid": False}, "ssl_short_lived": 0, "ssl_known_issuer": 0,
        "has_https": 1, "url_length": 30, "num_special_chars": 2,
        "has_many_query_params": 0, "contains_suspicious_query": 0, "entropy_hint": .5,
    }
    score, _label, _reasons = calculate_risk(features)
    assert score >= 70


def test_ai_model_is_loaded_only_once(monkeypatch):
    from backend import ai_model
    calls = 0
    original_load = __import__("joblib").load

    def counted_load(path):
        nonlocal calls
        calls += 1
        return original_load(path)

    monkeypatch.setattr("joblib.load", counted_load)
    monkeypatch.setattr(ai_model, "_model", None)
    monkeypatch.setattr(ai_model, "_load_attempted", False)
    monkeypatch.setattr(ai_model, "_load_error", None)
    assert ai_model._load_model() is not None
    assert ai_model._load_model() is not None
    assert calls == 1


def test_allowlisted_domain_without_network_verification_is_heuristic_safe():
    result = analyze_url("https://google.com", use_network=False)
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] == 0
    assert result["analysis_complete"] is True
    assert result["analysis_mode"] == "heuristic_only"


def test_url_normalization_preserves_encoded_query_and_fragment():
    url = "HTTPS://EXAMPLE.COM/a%2Fb?signature=AbC%2F123#section"
    assert normalize_url(url) == "https://example.com/a%2Fb?signature=AbC%2F123#section"


def test_optional_network_failures_keep_numeric_heuristic_result(monkeypatch):
    from backend import engine
    monkeypatch.setattr(engine, "dns_lookup", lambda *_a, **_k: (_ for _ in ()).throw(OSError("dns failed")))
    monkeypatch.setattr(engine, "ssl_lookup", lambda *_a, **_k: (_ for _ in ()).throw(OSError("ssl failed")))
    monkeypatch.setattr(engine, "registration_lookup", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("rdap failed")))
    result = engine.analyze_url("https://example.test/a%2Fb?q=1#fragment", use_network=True)
    assert isinstance(result["risk_score"], (int, float))
    assert result["analysis_mode"] == "heuristic_only"
    assert {"dns_unavailable", "ssl_unavailable", "whois_unavailable"}.issubset(result["warnings"])
