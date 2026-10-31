"""
predict.py - SafeWeb URL Phishing Predictor

Loads the trained XGBoost calibrated model and assesses whether a given URL
is safe, suspicious, or phishing.

Three layers of defense:
  1. COMPREHENSIVE VALIDATION - rejects arbitrary random text, keyboard mashing,
     invalid URL syntax, and non-existent TLDs/domains.
  2. REPUTABLE DOMAIN EVALUATION - evaluates popular trusted domains realistically
     (safety scores 92-96/100, recognizing that NO website is 100% immune).
  3. HYBRID ML + THREAT HEURISTICS - evaluates unknown URLs using character
     patterns, brand spoofing, suspicious TLDs, IP hosts, and entropy.

Usage:
    python predict.py "https://google.com"
    python predict.py "http://192.168.1.1/admin"
    python predict.py                 # launches interactive mode
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure the backend directory is in sys.path so joblib can unpickle model_wrapper
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import joblib
import numpy as np
import pandas as pd
import tldextract

from features import (
    FEATURE_NAMES,
    FeatureExtractionError,
    extract_features_dict,
    normalize_url,
    parse_url,
)
import model_wrapper  # noqa: F401 - required for joblib unpickling

DEFAULT_MODEL_PATH = BACKEND_DIR / "models" / "website_safety_model.joblib"
DEFAULT_METADATA_PATH = BACKEND_DIR / "models" / "model_metadata.json"

# -------------------------------------------------------------------------
# TLD extract instance (offline snapshot bundled with tldextract)
# -------------------------------------------------------------------------
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# -------------------------------------------------------------------------
# Layer 1: Generalized Random Text & Non-Existent Domain Validation
# -------------------------------------------------------------------------
VOWELS = frozenset("aeiouy")
CONSONANTS_STREAK_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{6,}", re.IGNORECASE)

# Valid domain name label regex: 1-63 chars, alphanumeric with internal hyphens
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# Standard URL syntax matcher
_URL_SYNTAX_RE = re.compile(
    r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?"   # optional scheme
    r"(?:[^@\s]+@)?"                        # optional userinfo
    r"(?:"
        r"\d{1,3}(?:\.\d{1,3}){3}"          # IPv4
        r"|"
        r"\[[:0-9a-fA-F]+\]"                # IPv6 bracket
        r"|"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"   # hostname label
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
        r"\.[a-zA-Z]{2,}"                   # TLD (at least 2 letters)
    r")"
    r"(?::\d{1,5})?"                        # optional port
    r"(?:[/?#]\S*)?$",                      # optional path/query/fragment
    re.IGNORECASE
)


def _is_ip_host(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    parts = bare.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


def _is_gibberish_text(token: str) -> bool:
    """
    Detects random keyboard mash like 'asdfghjkl', 'zxcvbnm', 'qwrtsdfg',
    or strings without vowels in tokens >= 6 chars.
    """
    token_clean = re.sub(r"[^a-zA-Z]", "", token).lower()
    if len(token_clean) >= 6:
        # Long word with 0 vowels is almost certainly gibberish
        if not any(c in VOWELS for c in token_clean):
            return True
        # 6+ consecutive consonants in a row (e.g. 'asdfghjkl', 'zxcklvj')
        if CONSONANTS_STREAK_RE.search(token_clean):
            return True
    return False


@lru_cache(maxsize=1000)
def _check_dns_resolves(host: str) -> Optional[bool]:
    """
    Check if domain exists in DNS.
    Returns:
      True: domain resolved successfully
      False: domain definitely does not exist (NXDOMAIN)
      None: cannot determine (offline or network error)
    """
    try:
        socket.setdefaulttimeout(1.5)
        socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        # Check if the internet/DNS resolver itself is reachable
        try:
            socket.getaddrinfo("google.com", None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            # If google.com resolved but this domain failed, the domain does not exist!
            return False
        except Exception:
            # Entire network is offline or sandboxed
            return None
    except Exception:
        return None


def validate_input_url(raw_url: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """
    General validation for any input.
    Returns: (is_valid, error_message, normalized_url, host)
    """
    s = raw_url.strip()
    if not s:
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 1. Reject plain text with unencoded whitespace (queries, sentences, notes)
    if " " in s or "\t" in s or "\n" in s:
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 2. Check general URL syntax pattern
    if not _URL_SYNTAX_RE.match(s) and not _is_ip_host(s.split("/")[0].split("?")[0]):
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 3. Parse host and check structure
    try:
        parsed = parse_url(s)
        norm_url = parsed.normalized
        host = parsed.host.lower()
    except FeatureExtractionError:
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    if not host or len(host) > 253:
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 4. If host is an IP, it's structurally valid (will be judged by ML/heuristics)
    if _is_ip_host(host):
        return True, "", norm_url, host

    # 5. Domain label structure checks
    labels = host.split(".")
    if len(labels) < 2:
        # Bare name with no TLD (e.g. 'asdfghjkl', 'test', 'localhost')
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    for label in labels:
        if not label or len(label) > 63 or not _DOMAIN_LABEL_RE.match(label):
            return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 6. Check recognized TLD against the official Public Suffix List
    ext = _EXTRACT(host)
    if not ext.suffix or not ext.domain:
        # TLD doesn't exist in worldwide registry (e.g. .asdf, .fake, .notatld)
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 7. Check keyboard-mash gibberish in domain labels
    if _is_gibberish_text(ext.domain):
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    # 8. Live DNS check if network is available
    dns_status = _check_dns_resolves(host)
    if dns_status is False:
        return False, "Website doesn't exist - please enter a valid URL.", None, None

    return True, "", norm_url, host


# -------------------------------------------------------------------------
# Layer 2: Popular Trusted Domains
# -------------------------------------------------------------------------
# NOTE: No website is 100% safe. Even trusted domains can host malicious user
# content (Google Drive/Forms, GitHub raw files, open redirects).
# Therefore, reputable domains are assigned realistic high-safety scores
# (e.g. 92.0 - 96.0 / 100), never an absolute 100%.
TRUSTED_DOMAINS = frozenset({
    # Search engines
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    # Social media
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "pinterest.com", "tumblr.com", "tiktok.com", "snapchat.com",
    "threads.net", "mastodon.social",
    # Video / streaming
    "youtube.com", "netflix.com", "twitch.tv", "spotify.com", "vimeo.com",
    "disneyplus.com", "hulu.com", "primevideo.com",
    # Tech & developer
    "microsoft.com", "apple.com", "amazon.com", "github.com", "gitlab.com",
    "bitbucket.org", "stackoverflow.com", "mozilla.org", "firefox.com", "chromium.org",
    # Cloud & documentation
    "cloudflare.com", "digitalocean.com", "heroku.com", "netlify.com", "vercel.com",
    "azure.com", "npmjs.com", "pypi.org", "python.org", "numpy.org", "scipy.org",
    "pandas.pydata.org", "readthedocs.io", "readthedocs.org", "docs.rs",
    "reactjs.org", "vuejs.org", "angular.io", "nextjs.org", "docker.com",
    "kubernetes.io", "jetbrains.com",
    # E-commerce
    "ebay.com", "shopify.com", "etsy.com", "walmart.com", "target.com",
    "alibaba.com", "flipkart.com", "myntra.com", "ajio.com",
    # Communication & tools
    "whatsapp.com", "telegram.org", "discord.com", "slack.com", "zoom.us",
    "skype.com", "signal.org", "notion.so", "trello.com", "canva.com", "figma.com",
    "dropbox.com", "box.com", "mega.nz", "adobe.com",
    # Email
    "gmail.com", "outlook.com", "protonmail.com", "mail.com", "zoho.com",
    # Knowledge & education
    "wikipedia.org", "wikimedia.org", "archive.org", "medium.com", "quora.com",
    "britannica.com", "khanacademy.org", "coursera.org", "edx.org", "udemy.com",
    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com", "nytimes.com",
    "theguardian.com", "washingtonpost.com", "forbes.com",
    # Finance & payments
    "paypal.com", "stripe.com", "razorpay.com", "wise.com",
    # Reference standards
    "who.int", "un.org", "w3.org", "ietf.org", "example.com", "example.org",
})


def _get_registered_domain(host: str) -> str:
    """Extract registered domain (e.g. 'docs.google.com' -> 'google.com')."""
    ext = _EXTRACT(host)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or host


# -------------------------------------------------------------------------
# Layer 3: Heuristic Threat Signals
# -------------------------------------------------------------------------
RISKY_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq",  # Free Freenom domains
    "top", "xyz", "club", "buzz", "surf", "rest", "icu", "cam",
    "monster", "cyou", "cfd", "click", "link", "loan", "work",
    "racing", "win", "gdn", "bid", "stream", "download", "date",
})

TARGETED_BRANDS = frozenset({
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "linkedin",
    "twitter", "dropbox", "icloud", "chase", "wellsfargo",
    "bankofamerica", "hsbc", "citibank", "dhl", "fedex", "ups", "usps",
    "outlook", "office365", "onedrive", "sharepoint", "steam",
    "coinbase", "binance", "metamask", "paytm", "phonepe", "sbi", "hdfc",
})


def _compute_heuristic_score(host: str, feats: Dict[str, float]) -> Tuple[float, List[str]]:
    """Evaluates rule-based threat signals and returns (penalty_score, indicators)."""
    score = 0.0
    indicators: List[str] = []
    ext = _EXTRACT(host)
    reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
    domain_lower = ext.domain.lower() if ext.domain else ""

    # Raw IP address
    if feats.get("has_ip_address", 0) == 1:
        score += 0.35
        indicators.append("Host is a raw numeric IP address instead of a domain name")

    # Obfuscation symbols
    if feats.get("has_at_symbol", 0) == 1:
        score += 0.25
        indicators.append("URL contains '@' symbol (often used to obscure destination)")

    if feats.get("has_unusual_port", 0) == 1:
        score += 0.20
        indicators.append("Non-standard web port detected")

    if feats.get("has_punycode", 0) == 1:
        score += 0.25
        indicators.append("Punycode detected (possible homograph/lookalike attack)")

    # Brand impersonation check
    for brand in TARGETED_BRANDS:
        if brand in domain_lower and reg_domain not in TRUSTED_DOMAINS:
            score += 0.30
            indicators.append(f"Brand name '{brand}' found in domain, but this is NOT the official '{brand}' website")
            break

    # High-risk phishing TLD
    if ext.suffix and ext.suffix.lower() in RISKY_TLDS:
        score += 0.20
        indicators.append(f"High-risk TLD '.{ext.suffix}' frequently abused by phishing campaigns")

    # Excessive hyphens
    host_hyphens = int(feats.get("host_hyphens", 0))
    num_hyphens = int(feats.get("num_hyphens", 0))
    if host_hyphens >= 4:
        score += 0.25
        indicators.append(f"Excessive hyphens ({host_hyphens}) in domain name")
    elif num_hyphens >= 4:
        score += 0.20
        indicators.append(f"Excessive hyphens ({num_hyphens}) in URL")
    elif num_hyphens >= 3:
        score += 0.10
        indicators.append(f"Multiple hyphens ({num_hyphens}) in URL")

    # Subdomains
    num_subdomains = int(feats.get("num_subdomains", 0))
    if num_subdomains >= 4:
        score += 0.20
        indicators.append(f"Many subdomains ({num_subdomains}) detected")
    elif num_subdomains >= 3:
        score += 0.10
        indicators.append(f"Multiple subdomains ({num_subdomains}) detected")

    # High randomness
    if feats.get("domain_entropy", 0.0) >= 4.0:
        score += 0.15
        indicators.append("Very high domain randomness/entropy (looks machine-generated)")
    elif feats.get("domain_entropy", 0.0) >= 3.8:
        score += 0.08
        indicators.append("High domain randomness/entropy")

    # Path tricks
    if feats.get("has_double_slash_in_path", 0) == 1:
        score += 0.10
        indicators.append("Double slash '//' in path (possible redirect trick)")

    # URL Shorteners
    if feats.get("is_shortener", 0) == 1:
        score += 0.10
        indicators.append("Known URL shortener service (destination is hidden)")

    # Excessive URL length
    url_length = int(feats.get("url_length", 0))
    if url_length > 150:
        score += 0.15
        indicators.append(f"Very long URL ({url_length} chars)")

    return score, indicators


class URLSafetyPredictor:
    """SafeWeb production predictor with realistic safety scoring."""

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        metadata_path: Path = DEFAULT_METADATA_PATH,
    ):
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at: {model_path}\n"
                f"Please ensure train_model.py has run successfully."
            )

        self.model = joblib.load(model_path)
        self.model_name = getattr(self.model, "base_name", "xgboost")
        self.calibration_method = getattr(self.model, "method", "isotonic")

        # Thresholds on combined risk score (0.0 to 1.0)
        self.t_safe = 0.40      # risk <= 40% (Safety Score >= 60/100) -> SAFE
        self.t_phish = 0.60     # risk >= 60% (Safety Score <= 40/100) -> PHISHING

    def predict(self, raw_url: str) -> Dict[str, Any]:
        """
        Assess a URL and return Safety Score (out of 100), Phishing Risk,
        Verdict, and detected risk indicators.
        """
        raw_url = raw_url.strip()

        # ---- Layer 1: Generalized Validation ----
        is_valid, err_msg, norm_url, host = validate_input_url(raw_url)
        if not is_valid:
            return self._invalid_result(raw_url, err_msg)

        reg_domain = _get_registered_domain(host)

        # Extract features
        try:
            feats = extract_features_dict(raw_url)
        except FeatureExtractionError:
            return self._invalid_result(raw_url, "Website doesn't exist - please enter a valid URL.")

        # ---- Layer 2: Popular Trusted Domain Handling ----
        # No website is 100% safe. Even trusted websites can have open redirects
        # or hosted phishing pages (e.g. Google Sites/Drive phishing).
        if reg_domain in TRUSTED_DOMAINS:
            _, trust_indicators = _compute_heuristic_score(host, feats)
            trust_indicators = [i for i in trust_indicators if "Brand name" not in i]

            # Base risk for reputable sites is realistically 3.5% - 7.5%
            # (Safety Score: 92.5 - 96.5 / 100)
            base_risk = 4.5
            if trust_indicators:
                base_risk += len(trust_indicators) * 6.0

            risk_pct = round(min(base_risk, 35.0), 1)
            # Realistic safety score out of 100
            safety_score = round(100.0 - risk_pct, 1)

            return {
                "url": raw_url,
                "normalized_url": norm_url,
                "registered_domain": reg_domain,
                "verdict": "SAFE",
                "safety_score": safety_score,
                "risk_score_pct": risk_pct,
                "probability": round(risk_pct / 100.0, 4),
                "confidence_pct": 95.0,
                "explanation": f"'{reg_domain}' is a well-known trusted domain. Note: No website is 100% immune to compromised links or user-generated pages.",
                "risk_indicators": trust_indicators,
                "features": feats,
            }

        # ---- Layer 3: Hybrid ML + Security Heuristics ----
        df_row = pd.DataFrame([feats], columns=FEATURE_NAMES)
        ml_proba = float(self.model.predict_phishing_proba(df_row)[0])

        heuristic_penalty, risk_indicators = _compute_heuristic_score(host, feats)

        if heuristic_penalty > 0:
            # Active red flags amplify the risk
            combined = ml_proba + heuristic_penalty * (1.0 - ml_proba)
        else:
            # No red flags: cap ML-alone score at 55% so benign URLs don't get falsely flagged
            combined = min(ml_proba, 0.55)

        combined = float(np.clip(combined, 0.04, 0.98))
        risk_pct = round(combined * 100, 1)

        # Safety Score out of 100 (capped at 96.0 because no website is 100% safe)
        safety_score = round(max(2.0, min(96.0, 100.0 - risk_pct)), 1)

        if combined <= self.t_safe:
            verdict = "SAFE"
            confidence = round((1.0 - combined) * 100, 1)
            explanation = "URL demonstrates standard benign patterns with no major threat signals."
        elif combined >= self.t_phish:
            verdict = "PHISHING"
            confidence = round(combined * 100, 1)
            explanation = "URL exhibits strong phishing and threat indicators. Do NOT enter sensitive data."
        else:
            verdict = "SUSPICIOUS"
            confidence = round(50.0 + abs(combined - 0.5) * 100, 1)
            explanation = "URL contains mixed or abnormal attributes. Proceed with caution."

        return {
            "url": raw_url,
            "normalized_url": norm_url,
            "registered_domain": reg_domain,
            "verdict": verdict,
            "safety_score": safety_score,
            "risk_score_pct": risk_pct,
            "probability": round(combined, 4),
            "ml_score_pct": round(ml_proba * 100, 1),
            "heuristic_penalty_pct": round(heuristic_penalty * 100, 1),
            "confidence_pct": confidence,
            "explanation": explanation,
            "risk_indicators": risk_indicators,
            "features": feats,
        }

    def _invalid_result(self, raw_url: str, message: str) -> Dict[str, Any]:
        return {
            "url": raw_url,
            "error": message,
            "verdict": "INVALID",
            "safety_score": None,
            "risk_score_pct": None,
            "probability": None,
            "confidence_pct": None,
            "explanation": message,
            "risk_indicators": [],
        }


def format_cli_output(res: Dict[str, Any]) -> str:
    """Format the prediction result into a clean terminal report."""
    if res.get("verdict") == "INVALID":
        return (
            f"\n{'=' * 60}\n"
            f" [!] INVALID INPUT\n"
            f"{'=' * 60}\n"
            f" Input   : {res['url']}\n"
            f" Message : {res.get('error', res.get('explanation', ''))}\n"
            f"{'=' * 60}\n"
        )

    verdict = res["verdict"]
    banner = {
        "SAFE": "[SAFE / LEGITIMATE]",
        "SUSPICIOUS": "[? SUSPICIOUS / CAUTION]",
        "PHISHING": "[!! PHISHING / DANGEROUS]",
    }.get(verdict, verdict)

    lines = [
        "",
        "=" * 60,
        " SafeWeb URL Safety Analysis",
        "=" * 60,
        f" Input URL     : {res['url']}",
        f" Canonical     : {res.get('normalized_url', 'N/A')}",
        f" Domain        : {res.get('registered_domain', 'N/A')}",
        "-" * 60,
        f" Verdict       : {banner}",
        f" Safety Score  : {res['safety_score']} / 100",
        f" Phishing Risk : {res['risk_score_pct']}%",
    ]

    if res.get("ml_score_pct") is not None:
        lines.append(f"   ML Model    : {res['ml_score_pct']}% risk")
        lines.append(f"   Heuristics  : +{res.get('heuristic_penalty_pct', 0)}% penalty")

    lines.append(f" Summary       : {res['explanation']}")

    if res.get("risk_indicators"):
        lines.append("-" * 60)
        lines.append(" Risk Indicators:")
        for indicator in res["risk_indicators"]:
            lines.append(f"  * {indicator}")
    else:
        lines.append("-" * 60)
        lines.append(" Risk Indicators: None detected")

    lines.append("=" * 60)
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze URLs for safety and phishing risk.")
    parser.add_argument("url", nargs="?", help="URL to inspect")
    parser.add_argument("--json", action="store_true", help="Output results in raw JSON format")
    args = parser.parse_args()

    try:
        predictor = URLSafetyPredictor()
    except Exception as e:
        print(f"[!] Initialization Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.url:
        result = predictor.predict(args.url)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(format_cli_output(result))
        return

    print("\n" + "=" * 60)
    print(" SafeWeb Interactive URL Safety Inspector")
    print(" (Enter a URL to analyze. Type 'exit' or 'q' to quit)")
    print("=" * 60 + "\n")

    while True:
        try:
            user_input = input("Enter URL > ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("Exiting. Stay safe!")
                break
            result = predictor.predict(user_input)
            print(format_cli_output(result))
        except (KeyboardInterrupt, EOFError):
            print("\nExiting. Stay safe!")
            break


if __name__ == "__main__":
    main()
