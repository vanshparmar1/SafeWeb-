"""
main.py - SafeWeb URL Phishing Detection FastAPI Service

High-performance REST API and Web Dashboard for real-time URL phishing risk assessment.

Run server:
    python main.py
Or with uvicorn directly:
    uvicorn main:app --reload --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure backend directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from predict import URLSafetyPredictor

# Lazy singleton predictor
_predictor: Optional[URLSafetyPredictor] = None


def get_predictor() -> URLSafetyPredictor:
    """Retrieve or initialize the singleton ML predictor."""
    global _predictor
    if _predictor is None:
        _predictor = URLSafetyPredictor()
    return _predictor


# Initialize FastAPI application
app = FastAPI(
    title="SafeWeb URL Safety & Phishing Detection API",
    description="Machine Learning REST API to predict phishing risks and analyze lexical URL threats in real-time.",
    version="1.0.0",
)

# Enable CORS for all frontends, dev servers (e.g. Vite on 5173), and browser extensions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Request & Response Schemas (Pydantic v2)
# --------------------------------------------------------------------------
class URLAnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        description="The full URL or web address to analyze",
        examples=["https://secure-login.bank-update.xyz/login"],
    )


class BatchAnalyzeRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        description="List of URLs to analyze (max 100 per request)",
        max_length=100,
        examples=[["https://google.com", "http://192.168.1.1/admin"]],
    )


class AnalysisResult(BaseModel):
    url: str
    normalized_url: Optional[str] = None
    registered_domain: Optional[str] = None
    verdict: str = Field(description="SAFE, SUSPICIOUS, PHISHING, or INVALID")
    safety_score: Optional[float] = Field(None, description="Safety rating out of 100 (e.g. 95.5 / 100)")
    risk_score_pct: Optional[float] = Field(None, description="Probability of phishing in percent (0-100%)")
    confidence_pct: Optional[float] = Field(None, description="Confidence percentage for the assigned verdict")
    explanation: str
    risk_indicators: List[str] = Field(default_factory=list)
    features: Optional[Dict[str, float]] = None
    error: Optional[str] = None
    latency_ms: float = Field(description="Inference time in milliseconds")


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: Optional[str]
    calibration_method: Optional[str]
    timestamp_utc: str


# --------------------------------------------------------------------------
# Helper Function
# --------------------------------------------------------------------------
def analyze_single_url(raw_url: str) -> AnalysisResult:
    try:
        pred = get_predictor()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"ML model failed to load: {e}",
        )

    start_time = time.perf_counter()
    res = pred.predict(raw_url)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return AnalysisResult(
        url=res["url"],
        normalized_url=res.get("normalized_url"),
        registered_domain=res.get("registered_domain"),
        verdict=res["verdict"],
        safety_score=res.get("safety_score"),
        risk_score_pct=res.get("risk_score_pct"),
        confidence_pct=res.get("confidence_pct"),
        explanation=res.get("explanation", res.get("error", "")),
        risk_indicators=res.get("risk_indicators", []),
        features=res.get("features"),
        error=res.get("error"),
        latency_ms=latency_ms,
    )


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.get("/", tags=["General"])
def root(request: Request):
    """
    Serves the React + Vite Web Dashboard if available; otherwise returns API metadata.
    """
    # Prefer built React SPA in dist/
    index_file = DIST_DIR / "index.html"
    if not index_file.exists():
        index_file = FRONTEND_DIR / "index.html"

    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header and index_file.exists():
        return FileResponse(index_file)

    # API metadata
    return {
        "service": "SafeWeb Phishing Detection API",
        "version": "1.0.0",
        "status": "online",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "model_info": "/api/model-info",
            "analyze_post": "/api/analyze",
            "quick_check_get": "/api/quick-check?url={url}",
            "batch_analyze_post": "/api/batch-analyze",
        },
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
def health_check():
    """Returns the operational status of the service and model loading state."""
    pred = None
    try:
        pred = get_predictor()
    except Exception:
        pass

    return HealthResponse(
        status="healthy" if pred is not None else "degraded",
        model_loaded=pred is not None,
        model_name=getattr(pred, "model_name", None),
        calibration_method=getattr(pred, "calibration_method", None),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/api/model-info", tags=["Model"])
def model_info():
    """Returns details about the trained classifier, calibration, and thresholds."""
    try:
        pred = get_predictor()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Model is currently not loaded: {e}",
        )

    return {
        "model_name": pred.model_name,
        "calibration_method": pred.calibration_method,
        "decision_thresholds": {
            "safe_threshold": pred.t_safe,
            "phishing_threshold": pred.t_phish,
            "safety_scale": "0 to 100 (No website is 100% immune; max realistic safety capped at 96.0)",
            "interpretation": {
                "Safety Score >= 60.0 / 100 (Risk <= 40%)": "SAFE (likely legitimate)",
                "Safety Score <= 40.0 / 100 (Risk >= 60%)": "PHISHING (likely malicious)",
                "Safety Score 40.0 to 60.0": "SUSPICIOUS / INCONCLUSIVE (caution recommended)",
            },
        },
    }


@app.post("/api/analyze", response_model=AnalysisResult, tags=["Detection"])
def analyze_url(payload: URLAnalyzeRequest):
    """
    Perform deep analysis on a single URL.
    Returns verdict, Safety Score (out of 100), Phishing Risk %, and threat indicators.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return analyze_single_url(payload.url.strip())


@app.get("/api/quick-check", response_model=AnalysisResult, tags=["Detection"])
def quick_check(url: str = Query(..., description="Target URL to inspect", min_length=1)):
    """
    Convenient GET endpoint for quick browser extension integration or link tests.
    """
    return analyze_single_url(url.strip())


@app.post("/api/batch-analyze", response_model=List[AnalysisResult], tags=["Detection"])
def batch_analyze(payload: BatchAnalyzeRequest):
    """
    Analyze up to 100 URLs in a single request.
    """
    if not payload.urls:
        return []
    return [analyze_single_url(u.strip()) for u in payload.urls if u.strip()]


# --------------------------------------------------------------------------
# Mount static assets for React + Vite (assets/ and static/)
# --------------------------------------------------------------------------
if (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="dist_assets")

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# --------------------------------------------------------------------------
# Direct execution helper
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0"
    print(f"[*] Starting SafeWeb API on http://{host}:{port} ...")
    uvicorn.run("main:app", host=host, port=port, reload=False)
