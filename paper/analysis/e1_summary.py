#!/usr/bin/env python3
"""E1 summary: parse firmware/logs/device-monitor-*.log (benchmark CSV) into per-boot samples.
Each boot that reaches the CSV rows contributes one sample per (algo, op). Writes
paper/data/E1/summary.csv and prints a table. Usage: python paper/analysis/e1_summary.py"""
import re, glob, os, statistics as st, csv, collections
root = os.path.join(os.path.dirname(__file__), "..", "..")
files = sorted(glob.glob(os.path.join(root, "firmware", "logs", "device-monitor-*.log")))
row = re.compile(r"^([A-Za-z0-9\-]+),(keygen|encaps|decaps|sign|verify|ecdh_compute_shared),(\d+),(\d+),(\d+),ok\s*$")
samples = collections.defaultdict(list)   # (algo,op) -> [us]
per_file = {}
for f in files:
    boots = 0
    text = open(f, errors="replace").read()
    if "largest_free_block" not in text:   # older firmware build (64 KiB stack, different binary): excluded
        continue
    for line in text.replace("\r", "\n").split("\n"):
        if line.startswith("algo,op"): boots += 1
        m = row.match(line.strip())
        if m: samples[(m.group(1), m.group(2))].append(int(m.group(3)))
    per_file[os.path.basename(f)] = boots
order = ["ML-KEM-512","ML-KEM-768","ML-KEM-1024","ML-DSA-44","ML-DSA-65","ML-DSA-87","X25519","ECDSA-P256"]
out = os.path.join(root, "paper", "data", "E1", "summary.csv")
with open(out, "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["algo","op","n","median_ms","min_ms","p95_ms","max_ms"])
    for algo in order:
        for (a, op), v in sorted(samples.items()):
            if a != algo or not v: continue
            v = sorted(v); p95 = v[min(len(v)-1, int(0.95*len(v)))]
            w.writerow([a, op, len(v), f"{st.median(v)/1000:.2f}", f"{v[0]/1000:.2f}", f"{p95/1000:.2f}", f"{v[-1]/1000:.2f}"])
print(open(out).read()); print("boots with data per file:", per_file)
