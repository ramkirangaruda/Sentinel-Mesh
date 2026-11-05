#!/usr/bin/env python3
"""INA219 calibration helper: one load per call, prints the paper/setup.md row.

  python paper/tools/calibrate.py --port COM7 --label "3x 56 ohm series" --volts 4.98 --ohms 168.2

Reads M's per-second `LOG cal ... current_ma=...` lines for --seconds (default
20), averages them, subtracts the zero offset (default -0.30 mA, measured
2026-10-15 with the input open), and compares with the multimeter reference
I = V / R (volts across the load with power on, ohms of the load with power
off; never use the meter as an ammeter). Appends the result to
paper/data/calibration.csv and saves the raw lines it read next to it.

Use --log FILE instead of --port to compute from a saved monitor log.
Close any `pio device monitor` on M first: only one program can hold the port.
To measure the offset itself, run with the input open and --volts 0 --ohms 0.
"""
import argparse, csv, os, re, statistics, sys, time
from datetime import datetime

CAL = re.compile(r"LOG cal n=\d+ shunt_mv=(-?[\d.]+) bus_v=(-?[\d.]+) current_ma=(-?[\d.]+)")


def read_port(port, seconds):
    import serial
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = port, 115200, 0.2
    s.dtr = s.rts = False  # do not reset M on open
    s.open()
    lines, buf, end = [], b"", time.time() + seconds
    try:
        while time.time() < end:
            buf += s.read(512)
            while b"\n" in buf:
                ln, buf = buf.split(b"\n", 1)
                lines.append(ln.decode("utf-8", "replace").rstrip("\r"))
    finally:
        s.close()
    return lines


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--port", help="M's COM port")
    src.add_argument("--log", help="saved monitor log instead of a live port")
    ap.add_argument("--label", required=True, help='load name, e.g. "1 kohm"')
    ap.add_argument("--volts", type=float, required=True, help="multimeter V across the load (0 for open)")
    ap.add_argument("--ohms", type=float, required=True, help="multimeter R of the load, power off (0 for open)")
    ap.add_argument("--offset", type=float, default=-0.30, help="zero offset in mA")
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--out", default=os.path.join("paper", "data", "calibration.csv"))
    a = ap.parse_args()

    if a.port:
        print(f"reading {a.port} for {a.seconds} s ...")
        lines = read_port(a.port, a.seconds)
    else:
        lines = open(a.log, encoding="utf-8", errors="replace").read().splitlines()
    vals = [(float(m[1]), float(m[2]), float(m[3])) for m in map(CAL.search, lines) if m]
    if len(vals) < 3:
        print(f"only {len(vals)} `LOG cal` lines found. Is M flashed with monitor_ina219 and the INA219 wired?")
        return 1
    cur = [v[2] for v in vals]
    sensor = statistics.mean(cur)
    corrected = sensor - a.offset
    ref = (a.volts / a.ohms * 1000.0) if a.ohms > 0 else 0.0
    err = (corrected - ref) / ref * 100.0 if ref else float("nan")
    print(f"n={len(cur)}  sensor mean {sensor:.3f} mA (sd {statistics.pstdev(cur):.3f})  "
          f"bus {statistics.mean(v[1] for v in vals):.3f} V")
    print(f"minus offset {a.offset:+.2f} -> {corrected:.3f} mA;  reference {a.volts:.3f} V / {a.ohms:.2f} ohm = {ref:.3f} mA")
    print(f"error {err:+.2f} %" if ref else "open input: this is the offset")
    print("\nrow for paper/setup.md:")
    print(f"| {a.label} | {a.volts:.3f} V, {a.ohms:.2f} ohm, {ref:.2f} mA | {corrected:.2f} mA | "
          + (f"{err:+.2f} % |" if ref else " |"))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new = not os.path.exists(a.out)
    with open(a.out, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["stamp", "label", "volts", "ohms", "ref_ma", "sensor_ma", "offset_ma",
                        "corrected_ma", "error_pct", "n", "sd_ma"])
        w.writerow([stamp, a.label, a.volts, a.ohms, f"{ref:.3f}", f"{sensor:.3f}", a.offset,
                    f"{corrected:.3f}", f"{err:.2f}", len(cur), f"{statistics.pstdev(cur):.3f}"])
    if a.port:
        raw = os.path.join(os.path.dirname(a.out), f"calibration_raw_{stamp}.log")
        open(raw, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print(f"saved {a.out} and {raw}")


if __name__ == "__main__":
    sys.exit(main())
