"""Tests that guard the training/inference contract of features.py."""
import math

import pytest

from features import (
    FEATURE_NAMES,
    FeatureExtractionError,
    extract_feature_vector,
    extract_features_dict,
    normalize_url,
    parse_url,
    registered_domain,
)


def test_feature_names_unique_and_vector_matches_order():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    d = extract_features_dict("https://example.com/a/b?x=1")
    assert list(d.keys()) == FEATURE_NAMES
    assert extract_feature_vector("https://example.com/a/b?x=1") == [d[n] for n in FEATURE_NAMES]


@pytest.mark.parametrize("variant", [
    "http://example.com/a?x=1", "https://example.com/a?x=1",
    "https://www.example.com/a?x=1", "HTTPS://WWW.EXAMPLE.COM/a?x=1",
    "example.com/a?x=1", "  https://example.com/a?x=1#frag  ",
])
def test_scheme_www_case_and_fragment_do_not_change_features(variant):
    """The dataset-leakage fix: scheme / www must not influence the model."""
    assert extract_feature_vector(variant) == extract_feature_vector("example.com/a?x=1")


def test_normalize_url_basics():
    assert normalize_url("https://www.Example.com/") == "example.com"
    assert normalize_url("http://user@Host.com:8080/p?q=1#f") == "user@host.com:8080/p?q=1"
    # only the host is lower-cased; the path keeps its case
    assert normalize_url("Host.COM/Keeps/Case.html") == "host.com/Keeps/Case.html"


def test_path_case_is_preserved():
    assert normalize_url("example.com/ABC/def") == "example.com/ABC/def"


def test_ip_address_and_port_flags():
    f = extract_features_dict("http://192.168.0.1:8080/login")
    assert f["has_ip_address"] == 1 and f["has_unusual_port"] == 1
    g = extract_features_dict("https://example.com:443/")
    assert g["has_ip_address"] == 0 and g["has_unusual_port"] == 0
    assert extract_features_dict("http://3232235777/x")["has_ip_address"] == 1
    assert extract_features_dict("http://0xC0A80001/x")["has_ip_address"] == 1


def test_at_symbol_punycode_encoding_shortener_flags():
    assert extract_features_dict("http://paypal.com@evil.example.org/")["has_at_symbol"] == 1
    assert extract_features_dict("http://xn--pple-43d.com/")["has_punycode"] == 1
    assert extract_features_dict("example.com/a%20b")["has_url_encoding"] == 1
    assert extract_features_dict("https://bit.ly/abc123")["is_shortener"] == 1
    assert extract_features_dict("https://example.com/")["is_shortener"] == 0


def test_subdomain_count_and_registered_domain():
    f = extract_features_dict("a.b.login.example.com/x")
    assert f["num_subdomains"] == 3
    assert registered_domain("https://www.a.b.example.com/x") == "example.com"


def test_ratios_entropy_and_counts():
    f = extract_features_dict("example.com/a/b/c?x=1&y=2")
    assert f["num_path_segments"] == 3
    assert f["num_query_params"] == 2
    assert 0 <= f["digit_ratio"] <= 1 and 0 <= f["letter_ratio"] <= 1
    assert f["domain_entropy"] > 0
    assert extract_features_dict("aaaa.com")["domain_entropy"] < extract_features_dict("x9q2k7zp.com")["domain_entropy"]
    assert all(math.isfinite(v) for v in f.values())


@pytest.mark.parametrize("bad", ["", "   ", "https://", "http:///path", "://", None, 123])
def test_malformed_urls_raise_clean_error(bad):
    with pytest.raises(FeatureExtractionError):
        extract_features_dict(bad)


def test_weird_but_parseable_input_does_not_crash():
    for url in ["http://[::1]:80/x", "a@b@c.com/p", "example.com:abc/x", "ex ample.com/ü", "http://" + "a" * 3000 + ".com"]:
        try:
            extract_features_dict(url)
        except FeatureExtractionError:
            pass  # a clean, typed failure is acceptable; any other exception is not
