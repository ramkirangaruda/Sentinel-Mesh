#!/usr/bin/env python3
"""Fit the INA219 current reading against the multimeter reference.

  python paper/analysis/calibration_fit.py [paper/data/calibration.csv]

Uses session 2 only (labels starting "S2", 2026-10-24, new test leads, lead
resistance 0.6 ohm already subtracted from every R). Session 1 (2026-10-21) is
a trial run: its black lead was failing, so its resistances are not trusted.
Rows where the sensor saw no current (VIN- jumper unseated) are dropped.

Model: sensor_ma = gain * ref_ma + offset_ma (least squares). The corrected
current for any later reading is (sensor_ma - offset_ma) / gain. The reference
is the DT830D multimeter (I = V / R), so the fit is relative to that meter; its
own spec is roughly +/-0.5 % (DC V) and +/-0.8 % (ohms).
"""
import csv, sys

path = sys.argv[1] if len(sys.argv) > 1 else "paper/data/calibration.csv"
rows = [r for r in csv.DictReader(open(path, newline="")) if r["label"].startswith("S2")]
pts = []
for r in rows:
    ref, sen = float(r["ref_ma"]), float(r["sensor_ma"])
    if ref > 0 and sen < 1:  # no current reached the sensor: wiring fault, not data
        print(f"dropped (no current at sensor): {r['label']}")
        continue
    pts.append((r["label"], ref, sen, float(r["volts"])))

n = len(pts)
sx = sum(p[1] for p in pts); sy = sum(p[2] for p in pts)
sxx = sum(p[1] ** 2 for p in pts); sxy = sum(p[1] * p[2] for p in pts)
gain = (n * sxy - sx * sy) / (n * sxx - sx * sx)
offset = (sy - gain * sx) / n
print(f"\nsession 2: {n} points, sensor = {gain:.4f} x reference {offset:+.3f} mA")
print(f"i.e. the INA219 reads {100 * (gain - 1):+.2f} % against the DT830D, zero error {offset:+.3f} mA\n")
print(f"{'load':<44}{'ref mA':>9}{'sensor':>9}{'corrected':>11}{'resid %':>9}")
worst = 0.0
for label, ref, sen, _ in pts:
    cor = (sen - offset) / gain
    res = 100 * (cor - ref) / ref if ref else float("nan")
    if ref > 1:
        worst = max(worst, abs(res))
    print(f"{label[:43]:<44}{ref:9.3f}{sen:9.3f}{cor:11.3f}{res:9.2f}" if ref else
          f"{label[:43]:<44}{ref:9.3f}{sen:9.3f}{cor:11.3f}{'(zero)':>9}")
print(f"\nworst residual after correction (loads only): {worst:.2f} %")
