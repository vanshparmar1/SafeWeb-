import sys
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
import main


class DummyRequest:
    def __init__(self, accept: str = "application/json"):
        self.headers = {"accept": accept}


def test_root_endpoint():
    data = main.root(DummyRequest())
    assert data["status"] == "online"
    assert "documentation" in data
    assert data["version"] == "1.0.0"


def test_health_endpoint():
    data = main.health_check()
    assert data.status == "healthy"
    assert data.model_loaded is True
    assert data.model_name == "xgboost"
    assert data.calibration_method == "isotonic"


def test_model_info_endpoint():
    data = main.model_info()
    assert "decision_thresholds" in data
    assert "safe_threshold" in data["decision_thresholds"]
    assert "phishing_threshold" in data["decision_thresholds"]
    assert "safety_scale" in data["decision_thresholds"]


def test_analyze_valid_url():
    req = main.URLAnalyzeRequest(url="https://www.google.com/search?q=test")
    res = main.analyze_url(req)
    assert res.url == "https://www.google.com/search?q=test"
    assert res.verdict == "SAFE"
    assert res.safety_score is not None
    assert 60.0 <= res.safety_score <= 96.5  # Realistic safety score: never 100%
    assert isinstance(res.risk_score_pct, float)
    assert res.latency_ms >= 0


def test_analyze_suspicious_ip():
    req = main.URLAnalyzeRequest(url="http://192.168.1.1:8080/login")
    res = main.analyze_url(req)
    assert res.verdict in ("SUSPICIOUS", "PHISHING")
    assert res.safety_score is not None
    assert res.safety_score < 40.0  # High risk = low safety score
    assert any("Host is a raw numeric IP address" in s for s in res.risk_indicators)


def test_quick_check_get():
    res = main.quick_check(url="https://github.com/torvalds/linux")
    assert res.registered_domain == "github.com"
    assert res.verdict == "SAFE"
    assert res.safety_score is not None
    assert 90.0 <= res.safety_score <= 96.5


def test_batch_analyze():
    req = main.BatchAnalyzeRequest(
        urls=["https://www.google.com", "http://192.168.1.50/bank-auth"]
    )
    res_list = main.batch_analyze(req)
    assert len(res_list) == 2
    assert res_list[0].url == "https://www.google.com"
    assert res_list[0].safety_score is not None
    assert res_list[1].safety_score is not None


def test_invalid_random_text_url():
    req = main.URLAnalyzeRequest(url="asdfghjkl random text")
    res = main.analyze_url(req)
    assert res.verdict == "INVALID"
    assert res.safety_score is None
    assert "Website doesn't exist - please enter a valid URL." in res.explanation
