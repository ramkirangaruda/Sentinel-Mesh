#!/usr/bin/env python3
"""E1 summary. Parses firmware/logs/device-monitor-*.log written by the benchmark build that
prints `board_mac=...`. Groups samples by board MAC. Older logs (no MAC line, different binary)
are excluded. Writes paper/data/E1/summary_per_board.csv and summary_pooled.csv.
Usage: python paper/analysis/e1_summary.py"""
import re, glob, os, csv, statistics as st, collections
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
files = sorted(glob.glob(os.path.join(root, "firmware", "logs", "device-monitor-*.log")))
row = re.compile(r"^([A-Za-z0-9\-]+),(keygen|encaps|decaps|sign|verify|ecdh_compute_shared),(\d+),(\d+),(\d+),ok\s*$")
mac_re = re.compile(r"board_mac=([0-9a-f]{12})")
data = collections.defaultdict(lambda: collections.defaultdict(list))   # mac -> (algo,op) -> [us]
for f in files:
    mac = None
    for line in open(f, errors="replace").read().replace("\r", "\n").split("\n"):
        m = mac_re.search(line)
        if m: mac = m.group(1)
        r = row.match(line.strip())
        if r and mac: data[mac][(r.group(1), r.group(2))].append(int(r.group(3)))
def pretty(m):   # firmware prints the efuse MAC byte-reversed
    b = [m[i:i+2] for i in range(0, 12, 2)][::-1]; return ":".join(b)
order = ["ML-KEM-512","ML-KEM-768","ML-KEM-1024","ML-DSA-44","ML-DSA-65","X25519","ECDSA-P256"]
keys = sorted({k for d in data.values() for k in d}, key=lambda k: (order.index(k[0]) if k[0] in order else 99, k[1]))
d1 = os.path.join(root, "paper", "data", "E1")
with open(os.path.join(d1, "summary_per_board.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["board_mac","algo","op","n","median_ms","min_ms","max_ms"])
    for mac in sorted(data):
        for k in keys:
            v = sorted(data[mac].get(k, []))
            if v: w.writerow([pretty(mac), k[0], k[1], len(v), f"{st.median(v)/1000:.2f}", f"{v[0]/1000:.2f}", f"{v[-1]/1000:.2f}"])
print(f"boards: {len(data)}  ->", ", ".join(f"{pretty(m)} (n={len(next(iter(data[m].values())))})" for m in sorted(data)))
print(f"{'algo':12} {'op':20} {'median of board medians (ms)':>30} {'between-board range (ms)':>26} {'spread %':>9}")
with open(os.path.join(d1, "summary_pooled.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["algo","op","boards","median_of_board_medians_ms","board_min_ms","board_max_ms","between_board_spread_pct"])
    for k in keys:
        meds = [st.median(data[m][k])/1000 for m in data if data[m].get(k)]
        if not meds: continue
        mm = st.median(meds); sp = (max(meds)-min(meds))/mm*100
        w.writerow([k[0], k[1], len(meds), f"{mm:.2f}", f"{min(meds):.2f}", f"{max(meds):.2f}", f"{sp:.1f}"])
        print(f"{k[0]:12} {k[1]:20} {mm:30.2f} {min(meds):12.2f}-{max(meds):<12.2f} {sp:9.1f}")
