"""Structured related-work search: fixed queries against OpenAlex, arXiv and Crossref, raw results saved.

  python paper/analysis/related_search.py [--out paper/writing/search_2026-11-06] [--only openalex,arxiv,crossref]

Writes one JSON per (database, query) with every hit's title, authors, year, venue and DOI/URL, and `log.csv` with
date, database, query and hit count. Screening (which hits are relevant) is done by hand from these files and recorded in
paper/writing/related_work.md. Polite: one request at a time with a pause, a plain User-Agent, no keys.
"""
import csv, datetime, json, os, sys, time, urllib.parse, urllib.request
import xml.etree.ElementTree as ET

TOPICS = {
    "T1 PQC cost on microcontrollers": ["post-quantum cryptography energy microcontroller", "ML-KEM ESP32",
                                        "ML-DSA microcontroller", "Kyber Dilithium energy IoT", "post-quantum ESP32"],
    "T2 PQC handshake denial of service": ["post-quantum handshake denial of service", "post-quantum key exchange DoS",
                                           "handshake exhaustion attack", "post-quantum TLS denial of service"],
    "T3 battery exhaustion": ["battery exhaustion attack", "sleep deprivation attack", "energy depletion attack IoT",
                              "denial of sleep attack"],
    "T4 puzzles and cookies": ["client puzzles constrained devices", "DoS-resistant key exchange IoT",
                               "DTLS cookie denial of service"],
    "T5 learned admission": ["machine learning admission control handshake", "lightweight intrusion detection energy IoT DoS"],
    "T6 ESP-NOW": ["ESP-NOW security"],
    "T7 energy budgets": ["energy budget token bucket", "energy-aware denial of service defense IoT"],
    "T8 join procedures": ["LoRaWAN join denial of service", "Bluetooth Low Energy battery drain attack"],
}
# DBLP was tried first but answers automated requests with a bot check (2026-11-06), so OpenAlex stands in for it.
DATABASES = [("openalex", None), ("arxiv", None), ("crossref", None)]
UA = {"User-Agent": "SentinelMesh-related-work-search/1.0"}


def get(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return r.read()
        except Exception as e:   # noqa: BLE001 -- retry, then record the failure
            err = e
            time.sleep(5 * (attempt + 1))
    raise err


def dblp(q):
    d = json.loads(get("https://dblp.org/search/publ/api?" + urllib.parse.urlencode(dict(q=q, format="json", h=100))))
    hits = d["result"]["hits"].get("hit", [])
    out = []
    for h in hits:
        i = h["info"]
        a = i.get("authors", {}).get("author", [])
        a = a if isinstance(a, list) else [a]
        out.append(dict(title=i.get("title"), authors=[x.get("text") for x in a], year=i.get("year"), venue=i.get("venue"),
                        doi=i.get("doi"), url=i.get("ee")))
    return int(d["result"]["hits"]["@total"]), out


def arxiv(q):
    terms = " AND ".join(f'all:"{w}"' if " " in w else f"all:{w}" for w in q.split())
    x = ET.fromstring(get("http://export.arxiv.org/api/query?" + urllib.parse.urlencode(dict(search_query=terms, max_results=50))))
    ns = {"a": "http://www.w3.org/2005/Atom", "o": "http://a9.com/-/spec/opensearch/1.1/"}
    out = [dict(title=" ".join(e.find("a:title", ns).text.split()), authors=[n.find("a:name", ns).text for n in e.findall("a:author", ns)],
                year=e.find("a:published", ns).text[:4], venue="arXiv", doi=None, url=e.find("a:id", ns).text)
           for e in x.findall("a:entry", ns)]
    return int(x.find("o:totalResults", ns).text), out


def openalex(q):
    d = json.loads(get("https://api.openalex.org/works?" + urllib.parse.urlencode({"search": q, "per-page": 50})))
    out = [dict(title=i.get("title"), authors=[a["author"]["display_name"] for a in i.get("authorships", [])],
                year=i.get("publication_year"), venue=((i.get("primary_location") or {}).get("source") or {}).get("display_name"),
                doi=i.get("doi"), url=i.get("id"), cited_by=i.get("cited_by_count")) for i in d["results"]]
    return int(d["meta"]["count"]), out


def crossref(q):
    d = json.loads(get("https://api.crossref.org/works?" + urllib.parse.urlencode({"query.bibliographic": q, "rows": 30})))
    out = []
    for i in d["message"]["items"]:
        out.append(dict(title=(i.get("title") or [""])[0], authors=[f"{a.get('given', '')} {a.get('family', '')}".strip() for a in i.get("author", [])],
                        year=(i.get("issued", {}).get("date-parts") or [[None]])[0][0], venue=(i.get("container-title") or [""])[0],
                        doi=i.get("DOI"), url=i.get("URL")))
    return int(d["message"]["total-results"]), out   # Crossref totals count loose matches; only the top 30 are kept


DATABASES = [("openalex", openalex), ("arxiv", arxiv), ("crossref", crossref)]


def main():
    out_dir = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "writing", "search_2026-11-06")
    os.makedirs(out_dir, exist_ok=True)
    today = datetime.date.today().isoformat()
    only = sys.argv[sys.argv.index("--only") + 1].split(",") if "--only" in sys.argv else None
    log = os.path.join(out_dir, "log.csv")
    new = not os.path.exists(log)
    with open(log, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["date", "topic", "database", "query", "total_hits", "kept", "file", "error"])
        for topic, queries in TOPICS.items():
            for q in queries:
                for name, fn in DATABASES:
                    if only and name not in only:
                        continue
                    fname = f"{name}_{q.replace(' ', '_').replace('/', '_')}.json"
                    try:
                        total, hits = fn(q)
                        with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as g:
                            json.dump(dict(database=name, query=q, date=today, total=total, hits=hits), g, indent=1, ensure_ascii=False)
                        w.writerow([today, topic, name, q, total, len(hits), fname, ""])
                        print(f"{name:8} {total:>7} {q}")
                    except Exception as e:   # noqa: BLE001
                        w.writerow([today, topic, name, q, "", "", "", repr(e)[:200]])
                        print(f"{name:8}  FAILED {q}: {e!r}"[:200])
                    time.sleep(3)


if __name__ == "__main__":
    main()
