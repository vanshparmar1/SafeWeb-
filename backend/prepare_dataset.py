"""
prepare_dataset.py - turn the raw Kaggle file into a clean training CSV.

Input : dataset/raw/malicious_phish.csv   (columns: url, type)
Output: dataset/phishing_dataset.csv      (columns: url, label, domain)
        reports/dataset_report.txt        (what was removed and why)
        reports/excluded_mixed_domains.csv

Cleaning rules (each one is a decision from our dataset audit):
  1. Keep only 'benign' (0) and 'phishing' (1). Defacement/malware are
     different threats and came from different sources (they would add a
     source shortcut), so they are excluded.
  2. Normalise every URL with features.normalize_url (removes scheme and
     'www.', which differed wildly between classes for dataset-assembly reasons).
  2b. Reject malformed / scraping-artifact rows (binary garbage, URLs wrapped in
     quotes, backslash escapes, HTML entities like &amp;, invalid host names).
     Real URLs a user types never look like this, and in this dataset these
     artifacts come from specific sources, so they would be learnable shortcuts.
     Counts per rule and class are printed; samples go to reports/rejected_samples.csv.
  3. Remove duplicates, and URLs that carry BOTH labels.
  4. Remove 'mixed' domains: registered domains that appear in both classes
     (e.g. yahoo.com has benign AND 'phishing' rows). The label is unreliable
     for them, so they are excluded from training and testing. This list is
     saved so you can inspect it.
  5. Remove 'phishing' rows that sit on clearly legitimate or heavily shared
     domains: (a) a small MANUAL_NOISE_DOMAINS list found by reading the data
     (e.g. tools.ietf.org/html/rfc1049 is an RFC page, not phishing), and
     (b) if a Tranco file is supplied, every phishing row whose domain is in the
     Tranco top-N. Popular platforms (sharepoint, googleapis...) host both real
     files and abuse; a URL-shape model cannot tell them apart, so that is left
     to the reputation / content layers. Removed domains are saved for review.
  6. Cap URLs per domain per class (default 100) so a few giant sites such as
     wikipedia.org (12,874 URLs) cannot dominate or be memorised.
No oversampling is done here: balancing is handled later with class weights,
AFTER the data is split.
"""
from __future__ import annotations

import argparse
import io
import re
import sys
from pathlib import Path

import pandas as pd

from features import (FeatureExtractionError, normalize_url, parse_url,
                      registered_domain, registered_domain_from_host)

BASE = Path(__file__).resolve().parent
RAW = BASE / "dataset" / "raw" / "malicious_phish.csv"
OUT = BASE / "dataset" / "phishing_dataset.csv"
REPORT_DIR = BASE / "reports"
TRANCO = BASE / "dataset" / "raw" / "tranco.csv"   # optional, see load_tranco()

# Domains whose 'phishing' rows we READ and judged to be mislabelled.
# Evidence: tools.ietf.org/html/rfc1049 (an RFC document);
#           ddj.com/architect/184410014/ (a Dr. Dobb's article page).
# Add more here only after looking at real sample URLs.
MANUAL_NOISE_DOMAINS = {"ietf.org", "ddj.com"}

# Windows consoles can choke on unusual characters in URLs.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


_HOST_OK = re.compile(r"^[a-z0-9_.\-]+$|^\[[0-9a-f:.]+\]$")
_HTML_ENTITY = re.compile(r"&(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-f]+);", re.IGNORECASE)


def reject_reason(norm: str, host: str) -> str:
    """Return why a normalised URL is not a plausible real-world URL ('' = OK)."""
    if any(ord(c) < 33 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F or c == "\ufffd" for c in norm):
        return "control_or_space_chars"
    if norm[0] in "'\"" or norm[-1] in "'\"":
        return "quote_wrapped"
    if not _HOST_OK.match(host):
        return "invalid_host"
    if "\\" in norm:
        return "backslash"
    if _HTML_ENTITY.search(norm):
        return "html_entity"
    if len(norm) > 2048:
        return "over_2048_chars"
    return ""


def load_tranco(path: Path, top_n: int) -> set:
    """Read a Tranco CSV (rank,domain; header optional) -> set of registered domains."""
    t = pd.read_csv(path, header=None, names=["rank", "domain"], dtype=str,
                    usecols=[0, 1], encoding="utf-8")
    t["rank"] = pd.to_numeric(t["rank"], errors="coerce")
    t = t.dropna(subset=["rank", "domain"]).sort_values("rank").head(top_n)
    return {registered_domain_from_host(str(d).strip().lower()) for d in t["domain"]}


def clean(df_raw: pd.DataFrame, max_per_domain: int, seed: int, log,
          popular: set | None = None) -> pd.DataFrame:
    df = df_raw[["url", "type"]].dropna().copy()
    log(f"Raw rows: {len(df_raw):,}")

    df = df[df["type"].isin(["benign", "phishing"])].copy()
    df["label"] = (df["type"] == "phishing").astype(int)
    log(f"Rows with type benign/phishing: {len(df):,}")

    # --- normalise, validate, parse domain ---------------------------------
    norm, dom, reason = [], [], []
    for u in df["url"].astype(str):
        try:
            n = normalize_url(u)
            h = parse_url(n).host
            r = reject_reason(n, h)
            d = registered_domain_from_host(h) if not r else ""
            norm.append(n); dom.append(d); reason.append(r or ("" if d else "no_domain"))
        except Exception:
            norm.append(u); dom.append(""); reason.append("unparsable")
    df["norm"], df["domain"], df["reject"] = norm, dom, reason

    bad = df[df["reject"] != ""]
    if len(bad):
        tab = pd.crosstab(bad["reject"], bad["type"])
        log("Rejected as malformed / scraping artifacts (rule x class):")
        log(tab.to_string())
        REPORT_DIR.mkdir(exist_ok=True)
        samples = (bad.groupby("reject", group_keys=False).head(100)
                   .assign(sample=lambda x: x["url"].map(lambda s: repr(s)[:200])))
        samples[["reject", "type", "sample"]].to_csv(
            REPORT_DIR / "rejected_samples.csv", index=False, encoding="utf-8")
    log(f"Total rejected: {len(bad):,}")
    df = df[df["reject"] == ""].copy()
    df["url"] = df["norm"]

    # --- duplicates and conflicting labels --------------------------------
    n_lab = df.groupby("url")["label"].nunique()
    conflicts = n_lab[n_lab > 1].index
    df = df[~df["url"].isin(conflicts)]
    log(f"URLs with both labels (removed): {len(conflicts):,}")
    before = len(df)
    df = df.drop_duplicates("url")
    log(f"Duplicate URLs removed after normalisation: {before - len(df):,}")

    # --- mixed domains -----------------------------------------------------
    per = df.groupby(["domain", "label"]).size().unstack(fill_value=0)
    per.columns = ["n_benign", "n_phishing"]
    mixed = per[(per.n_benign > 0) & (per.n_phishing > 0)].copy()
    mixed["total"] = mixed.n_benign + mixed.n_phishing
    REPORT_DIR.mkdir(exist_ok=True)
    mixed.sort_values("total", ascending=False).to_csv(REPORT_DIR / "excluded_mixed_domains.csv")
    before = len(df)
    df = df[~df["domain"].isin(mixed.index)]
    log(f"Mixed domains excluded: {len(mixed):,} domains / {before - len(df):,} rows "
        f"(see reports/excluded_mixed_domains.csv)")

    # --- phishing rows on legitimate / heavily shared domains ----------------
    drop_domains = set(MANUAL_NOISE_DOMAINS) | (popular or set())
    is_phish = df["label"] == 1
    flagged = df[is_phish & df["domain"].isin(drop_domains)]
    if len(flagged):
        rep = (flagged.groupby("domain")
               .agg(n_phishing=("url", "size"), sample_url=("url", "first"))
               .sort_values("n_phishing", ascending=False))
        rep.to_csv(REPORT_DIR / "phishing_on_popular_domains.csv")
    df = df[~(is_phish & df["domain"].isin(drop_domains))]
    log(f"Phishing rows removed from legitimate/popular domains: {len(flagged):,} rows / "
        f"{flagged['domain'].nunique():,} domains "
        f"({'Tranco top-N + manual list' if popular else 'manual list only - no Tranco file'})")

    # --- per-domain cap (seeded, reproducible) -----------------------------
    before = len(df)
    df = (df.sample(frac=1.0, random_state=seed)
            .groupby(["domain", "label"], group_keys=False).head(max_per_domain))
    log(f"Removed by per-domain cap ({max_per_domain}): {before - len(df):,}")
    return df.sort_values(["domain", "url"]).reset_index(drop=True)[["url", "label", "domain"]]


def structure_report(df: pd.DataFrame, log) -> None:
    """Re-run the audit on cleaned data: shortcuts should now be smaller."""
    host = df["url"].str.split("/").str[0].str.split("?").str[0]
    path = df["url"].str.split("/", n=1).str[1].fillna("")
    s = pd.DataFrame({
        "has_path": path != "",
        "has_query": df["url"].str.contains("?", regex=False),
        "digits_in_host": host.str.contains(r"\d", regex=True),
        "hyphen_in_host": host.str.contains("-", regex=False),
    }).groupby(df["label"]).mean().round(3)
    s["median_len"] = df["url"].str.len().groupby(df["label"]).median()
    s["median_host_len"] = host.str.len().groupby(df["label"]).median()
    s.index = s.index.map({0: "benign", 1: "phishing"})
    log("\nStructure by class AFTER cleaning (check for big gaps = shortcuts):")
    log(s.to_string())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-per-domain", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--tranco", type=Path, default=TRANCO,
                    help="optional Tranco CSV (rank,domain); used if the file exists")
    ap.add_argument("--tranco-top", type=int, default=10000)
    ap.add_argument("--raw", type=Path, default=RAW)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    if not args.raw.exists():
        sys.exit(f"Raw file not found: {args.raw}")

    buf = io.StringIO()
    def log(msg: str = "") -> None:
        print(msg); buf.write(msg + "\n")

    popular = None
    if args.tranco.exists():
        popular = load_tranco(args.tranco, args.tranco_top)
        log(f"Loaded Tranco top {args.tranco_top:,}: {len(popular):,} registered domains")
    else:
        log(f"NOTE: {args.tranco} not found - only the manual noise list is applied.")

    df = clean(pd.read_csv(args.raw), args.max_per_domain, args.seed, log, popular)

    log(f"\nFINAL rows: {len(df):,}  |  unique domains: {df.domain.nunique():,}")
    counts = df["label"].value_counts().sort_index()
    log(f"benign (0): {counts.get(0, 0):,}   phishing (1): {counts.get(1, 0):,}   "
        f"phishing share: {df['label'].mean():.1%}")
    structure_report(df, log)

    log("\nLargest phishing domains kept (eyeball these for label noise):")
    top = df[df.label == 1].groupby("domain").size().sort_values(ascending=False).head(8)
    for d, c in top.items():
        sample = df[(df.domain == d) & (df.label == 1)]["url"].head(2).tolist()
        log(f"  {d:<28}{c:>5}   e.g. {sample}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False, encoding="utf-8")
    (REPORT_DIR / "dataset_report.txt").write_text(buf.getvalue(), encoding="utf-8")
    log(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
