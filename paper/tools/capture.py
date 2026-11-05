#!/usr/bin/env python3
"""Log several boards at once for a fixed time, with timestamps; sends nothing.

  python paper/tools/capture.py --port M=COM7 --port G=COM8 --seconds 60 --out paper/data/E_rig --tag first_check

Writes <out>/<stamp>_<tag>_<label>.log per board, each line prefixed with the
seconds since start (same format as run_flood_test.py). Ports are opened with
DTR/RTS low, so the boards are not reset. Close any monitor on those ports first.
"""
import argparse, os, sys, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from run_flood_test import open_port, Logger
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", action="append", required=True, help="LABEL=COMx, repeatable")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--out", default=os.path.join("paper", "data", "E_rig"))
    ap.add_argument("--tag", default="capture")
    ap.add_argument("--baud", type=int, default=115200)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, f"{datetime.now():%Y%m%d_%H%M%S}_{a.tag}")
    t0 = time.time()
    logs, sers = [], []
    for spec in a.port:
        label, port = spec.split("=", 1)
        s = open_port(port, a.baud)
        sers.append(s)
        lg = Logger(label, s, f"{base}_{label}.log", t0)
        lg.start()
        logs.append(lg)
    print(f"logging {', '.join(a.port)} for {a.seconds} s ...")
    try:
        time.sleep(a.seconds)
    finally:
        for lg in logs:
            lg.stop = True
        time.sleep(0.5)
        for s in sers:
            s.close()
    for spec in a.port:
        print(f"  {base}_{spec.split('=', 1)[0]}.log")


if __name__ == "__main__":
    sys.exit(main())
