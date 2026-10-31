"""
features.py - URL normalisation and feature extraction for SafeWeb.

This file is the SINGLE source of truth for:
  * how a raw URL is normalised before the model sees it, and
  * which features the model uses, and in what order (FEATURE_NAMES).

Training (train_model.py) and prediction (predict.py) both import from here,
so the two can never silently drift apart.

Why we normalise (important lesson from our dataset audit):
  In the Kaggle data, 91% of benign URLs have no "http(s)://" and only 3% start
  with "www.", while 26% / 39% of phishing URLs do. A model trained on raw
  strings would learn "has a scheme / has www => phishing", which is a quirk of
  how the dataset was assembled, NOT real phishing behaviour. It would flag
  www.google.com. So we remove the scheme and a leading "www." from EVERY URL,
  in training and in production.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List

import tldextract

# --------------------------------------------------------------------------
# Versioning - saved into model_metadata.json so mismatches are detectable.
# --------------------------------------------------------------------------
FEATURE_VERSION = "1.0"
NORMALIZATION_STEPS = [
    "strip_whitespace",
    "remove_scheme",
    "lowercase_host",
    "remove_leading_www",
    "drop_fragment",
    "drop_bare_root_slash",
]

# Central, ORDERED feature list. Never reorder without retraining.
FEATURE_NAMES: List[str] = [
    # lengths
    "url_length", "domain_length", "path_length", "query_length",
    # counts
    "num_dots", "num_hyphens", "host_hyphens", "num_underscores",
    "num_special_chars", "num_subdomains", "num_query_params",
    "num_path_segments",
    # ratios
    "digit_ratio", "letter_ratio", "special_char_ratio",
    # flags (0/1)
    "has_ip_address", "has_at_symbol", "has_unusual_port", "has_punycode",
    "has_url_encoding", "is_shortener", "has_double_slash_in_path",
    # randomness / structure of the domain
    "domain_entropy", "path_entropy", "longest_domain_token",
    "digits_in_domain", "tld_length",
]

# Offline mode: use the public-suffix snapshot bundled with tldextract so the
# server never makes a network call just to parse a URL.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Well-known URL shorteners (a factual list, not a guess about "badness").
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "bit.do", "lnkd.in",
    "t.ly", "rb.gy", "s.id", "v.gd", "tr.im", "x.co",
})

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HEX_HOST_RE = re.compile(r"^0x[0-9a-f]+$")
_NORMAL_CHARS = set(".-_/")  # structural characters, not counted as "special"


class FeatureExtractionError(ValueError):
    """Raised when a URL is too malformed to extract features from."""


@dataclass(frozen=True)
class ParsedURL:
    """A normalised URL split into parts (we parse by hand because urllib
    behaves badly on scheme-less or malformed strings)."""
    normalized: str
    userinfo: str
    host: str
    port: str
    path: str
    query: str


# --------------------------------------------------------------------------
# Normalisation and parsing
# --------------------------------------------------------------------------
def normalize_url(raw: str) -> str:
    """Return the canonical form used everywhere (training AND inference)."""
    if not isinstance(raw, str):
        raise FeatureExtractionError("URL must be a string")
    s = _SCHEME_RE.sub("", raw.strip())
    s = s.split("#", 1)[0]  # fragments never reach the server
    if not s:
        raise FeatureExtractionError("empty URL")

    end = len(s)
    for ch in "/?":
        i = s.find(ch)
        if i != -1:
            end = min(end, i)
    authority, rest = s[:end].lower(), s[end:]

    userinfo, sep, hostport = authority.rpartition("@")
    if hostport.startswith("www.") and "." in hostport[4:]:
        hostport = hostport[4:]
    authority = f"{userinfo}{sep}{hostport}"

    if rest == "/":
        rest = ""
    return authority + rest


def parse_url(raw: str) -> ParsedURL:
    norm = normalize_url(raw)
    end = len(norm)
    for ch in "/?":
        i = norm.find(ch)
        if i != -1:
            end = min(end, i)
    authority, rest = norm[:end], norm[end:]
    path, _, query = rest.partition("?")

    userinfo, _, hostport = authority.rpartition("@")
    port = ""
    if hostport.startswith("["):  # IPv6 literal
        close = hostport.find("]")
        host = hostport[: close + 1] if close != -1 else hostport
        tail = hostport[close + 1:] if close != -1 else ""
        if tail.startswith(":") and tail[1:].isdigit():
            port = tail[1:]
    elif ":" in hostport:
        h, _, p = hostport.rpartition(":")
        if p.isdigit():
            host, port = h, p
        else:
            host = hostport
    else:
        host = hostport

    host = host.strip(".")
    # a real host needs at least one letter or digit (rejects "://", ":", "...")
    if not any(c.isalnum() for c in host):
        raise FeatureExtractionError("no host found")
    return ParsedURL(norm, userinfo, host, port, path, query)


@lru_cache(maxsize=200_000)
def registered_domain_from_host(host: str) -> str:
    """e.g. 'login.paypal.com' -> 'paypal.com'. Used to group splits by domain."""
    r = _EXTRACT(host)
    if r.suffix:
        return f"{r.domain}.{r.suffix}"
    return r.domain or host


def registered_domain(raw_url: str) -> str:
    return registered_domain_from_host(parse_url(raw_url).host)


# --------------------------------------------------------------------------
# Feature helpers
# --------------------------------------------------------------------------
def shannon_entropy(text: str) -> float:
    """Randomness of a string in bits per character (random-looking = high)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _is_ip_host(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # decimal ("3232235777") or hex ("0xC0A80001") IP tricks
    return h.isdigit() or bool(_HEX_HOST_RE.match(h))


def extract_features_dict(raw_url: str) -> Dict[str, float]:
    """Extract all features. Raises FeatureExtractionError on unusable input."""
    p = parse_url(raw_url)
    url, host = p.normalized, p.host
    n = max(len(url), 1)

    is_ip = _is_ip_host(host)
    ext = _EXTRACT(host)
    reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else (ext.domain or host)
    subdomains = [] if is_ip else [s for s in ext.subdomain.split(".") if s]

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    special = sum((not c.isalnum()) and c not in _NORMAL_CHARS for c in url)

    tokens = [t for t in re.split(r"[.\-]", host.strip("[]")) if t]
    query_params = [q for q in re.split(r"[&;]", p.query) if q]

    feats = {
        "url_length": len(url),
        "domain_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "host_hyphens": host.count("-"),
        "num_underscores": url.count("_"),
        "num_special_chars": special,
        "num_subdomains": len(subdomains),
        "num_query_params": len(query_params),
        "num_path_segments": len([s for s in p.path.split("/") if s]),
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "special_char_ratio": special / n,
        "has_ip_address": int(is_ip),
        "has_at_symbol": int("@" in url),
        "has_unusual_port": int(p.port not in ("", "80", "443")),
        "has_punycode": int("xn--" in host),
        "has_url_encoding": int(bool(_PCT_RE.search(url))),
        "is_shortener": int(reg in SHORTENER_DOMAINS),
        "has_double_slash_in_path": int("//" in p.path),
        "domain_entropy": shannon_entropy(host),
        "path_entropy": shannon_entropy(p.path),
        "longest_domain_token": max((len(t) for t in tokens), default=0),
        "digits_in_domain": sum(c.isdigit() for c in host),
        "tld_length": 0 if is_ip else len(ext.suffix),
    }
    return {k: float(feats[k]) for k in FEATURE_NAMES}  # fixed order, all floats


def extract_feature_vector(raw_url: str) -> List[float]:
    """Features as a list in FEATURE_NAMES order (what the model receives)."""
    d = extract_features_dict(raw_url)
    return [d[name] for name in FEATURE_NAMES]
