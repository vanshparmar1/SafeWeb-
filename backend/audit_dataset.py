import pandas as pd
import tldextract

# Offline mode: use the bundled public-suffix list, no network calls
ext = tldextract.TLDExtract(suffix_list_urls=())

d = pd.read_csv("dataset/raw/malicious_phish.csv")
d = d[d["type"].isin(["benign", "phishing"])].copy()
d["url"] = d["url"].astype(str).str.strip()
print("Rows (benign + phishing only):", len(d))

# 1. Conflicting labels and duplicates
n_labels = d.groupby("url")["type"].nunique()
conflicts = n_labels[n_labels > 1].index
print("URLs labelled BOTH benign and phishing:", len(conflicts))
d = d[~d["url"].isin(conflicts)].drop_duplicates("url")
print("Rows after dedupe + conflict removal:", len(d))
print(d["type"].value_counts().to_string())

# 2. Strip scheme, then compare structure by class
d["norm"] = d["url"].str.replace(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", regex=True)
host = (d["norm"].str.split("/").str[0].str.split("?").str[0]
        .str.split("#").str[0].str.split("@").str[-1].str.split(":").str[0].str.lower())
path = d["norm"].str.split("/", n=1).str[1].fillna("")
stats = pd.DataFrame({
    "starts_www": host.str.startswith("www."),
    "has_path": path != "",
    "has_query": d["norm"].str.contains(r"\?", regex=True),
    "ends_slash": d["norm"].str.endswith("/"),
    "has_digits_in_host": host.str.contains(r"\d", regex=True),
}).groupby(d["type"]).mean().round(3)
stats["median_len"] = d["norm"].str.len().groupby(d["type"]).median()
print("\nStructure by class (share of URLs):")
print(stats.to_string())

# 3. Domain-level view (matters for leak-free splits)
def reg_domain(h: str) -> str:
    r = ext(h)
    return f"{r.domain}.{r.suffix}" if r.suffix else (r.domain or h)

d["domain"] = host.map(reg_domain)
per_class = d.groupby("type")["domain"].nunique()
print("\nUnique registered domains per class:\n", per_class.to_string())
both = set(d[d.type == "benign"]["domain"]) & set(d[d.type == "phishing"]["domain"])
print("Domains appearing in BOTH classes:", len(both))
for cls in ["phishing", "benign"]:
    print(f"\nTop 8 domains by URL count ({cls}):")
    print(d[d.type == cls]["domain"].value_counts().head(8).to_string())

# 4. Top TLDs by class
d["tld"] = host.map(lambda h: ext(h).suffix)
print("\nTop TLD share by class:")
print(d.groupby("type")["tld"].value_counts(normalize=True)
      .groupby(level=0).head(6).round(3).to_string())