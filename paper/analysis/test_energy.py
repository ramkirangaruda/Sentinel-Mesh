#!/usr/bin/env python3
"""Tests for energy.py: python -m unittest paper/analysis/test_energy.py (from the repo root).

Checks the parser on a hand-made log and the correction against the real session-2
calibration logs and the corrected column of paper/setup.md."""
import csv, os, statistics, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import energy  # noqa: E402

DATA = os.path.join(HERE, "..", "data")

SAMPLE = """\
[    0.50s] LOG monitor boot complete
[    0.51s] monitor,op,us,mJ,peak_current_mA
[    1.50s] LOG cal n=989 shunt_mv=-0.020 bus_v=5.232 current_ma=-0.203 mean_mw=-1.060
[    1.50s] LOG monitor: negative power -- are the shunt's A0/A1 leads swapped?
[    2.50s] LOG cal n=990 shunt_mv=10.000 bus_v=5.100 current_ma=100.000 mean_mw=510.000
[    2.50s] NRG {"ts":2500,"power_mw":510.0,"volts":5.101,"amps":0.1001,"battery_pct":100.0}
[    2.90s] monitor,op_0,200000,100.000,180.00
[    3.50s] LOG cal n=990 shunt_mv=10.000 bus_v=5.000 current_ma=120.000 mean_mw=600.000
[    3.50s] NRG {"ts":3500,"power_mw":600.0,"volts":5.000,"amps":0.1200,"battery_pct":100.0}
[    4.50s] NRG {"ts":4500,"power_mw":400.0,"volts":5.000,"amps":0.0800,"battery_pct":100.0}
"""


class TestCorrection(unittest.TestCase):
    def test_inverse_of_fit(self):
        for i_true in (0.0, 5.0, 100.0, 232.0):
            raw = energy.GAIN * i_true + energy.OFFSET_MA
            self.assertAlmostEqual(energy.correct_current_ma(raw), i_true, places=9)

    def test_energy_offset_uses_volts_and_time(self):
        # 100 mJ raw over 0.2 s at 5 V: (100 + 0.428 * 5 * 0.2) / 1.0367
        self.assertAlmostEqual(energy.correct_energy_mj(100.0, 0.2, 5.0), (100.0 + 0.428) / 1.0367, places=9)
        # constant current I for t seconds at V: corrected energy equals V * I_true * t
        i_raw, v, t = 150.0, 5.0, 2.0
        self.assertAlmostEqual(energy.correct_energy_mj(v * i_raw * t, t, v),
                               v * energy.correct_current_ma(i_raw) * t, places=9)

    def test_uncertainty_bound(self):
        self.assertEqual(energy.current_uncertainty_ma(5.0), 0.2)
        self.assertAlmostEqual(energy.current_uncertainty_ma(200.0), 1.2)

    def test_constants_match_calibration_fit(self):
        rows = [r for r in csv.DictReader(open(os.path.join(DATA, "calibration.csv"), newline=""))
                if r["label"].startswith("S2") and not (float(r["ref_ma"]) > 0 and float(r["sensor_ma"]) < 1)]
        xs = [float(r["ref_ma"]) for r in rows]
        ys = [float(r["sensor_ma"]) for r in rows]
        n, sx, sy = len(xs), sum(xs), sum(ys)
        gain = (n * sum(x * y for x, y in zip(xs, ys)) - sx * sy) / (n * sum(x * x for x in xs) - sx * sx)
        offset = (sy - gain * sx) / n
        self.assertEqual(n, 7)
        self.assertAlmostEqual(gain, energy.GAIN, places=4)
        self.assertAlmostEqual(offset, energy.OFFSET_MA, places=3)


class TestRealCalibrationLogs(unittest.TestCase):
    # corrected column of paper/setup.md's session-2 table
    SETUP_CORRECTED = {"20261024_232904": 0.217, "20261024_232734": 5.390, "20261024_232430": 19.457,
                       "20261024_232201": 57.460, "20261024_231819": 94.358, "20261024_231338": 182.396,
                       "20261024_230902": 232.799}

    def test_parser_reproduces_setup_table(self):
        sensor = {r["stamp"]: float(r["sensor_ma"])
                  for r in csv.DictReader(open(os.path.join(DATA, "calibration.csv"), newline=""))}
        for stamp, corrected in self.SETUP_CORRECTED.items():
            log = energy.parse(os.path.join(DATA, f"calibration_raw_{stamp}.log"))
            cal = [s for s in log.seconds if s.source == "cal"]   # calibrate.py averaged only these
            self.assertGreaterEqual(len(cal), 19, msg=stamp)
            raw = statistics.mean(s.current_ma_raw for s in cal)
            self.assertAlmostEqual(raw, sensor[stamp], delta=0.05, msg=stamp)  # one cut line in a log moves it ~0.01
            got = statistics.mean(s.current_ma for s in cal)
            self.assertAlmostEqual(got, corrected, delta=0.05, msg=stamp)


class TestParser(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(SAMPLE)
        self.log = energy.parse(self.path)

    def tearDown(self):
        os.remove(self.path)

    def test_seconds_pair_cal_with_nrg(self):
        s = self.log.seconds
        self.assertEqual([x.source for x in s], ["cal", "cal", "cal", "nrg"])
        self.assertEqual([x.t for x in s], [1.5, 2.5, 3.5, 4.5])
        self.assertIsNone(s[0].device_ts_ms)       # negative power: no NRG line
        self.assertEqual(s[1].device_ts_ms, 2500)
        self.assertEqual(self.log.negative_power_lines, 1)
        self.assertTrue(self.log.host_time)
        self.assertAlmostEqual(s[3].current_ma_raw, 80.0)

    def test_op_row(self):
        (op,) = self.log.ops
        self.assertEqual((op.index, op.us, op.t), (0, 200000, 2.9))
        self.assertEqual(op.bus_v, 5.0)           # ended inside the second reported at 3.5 s (5.000 V)
        self.assertAlmostEqual(op.mj, (100.0 + 0.428 * 5.0 * 0.2) / 1.0367, places=9)
        self.assertAlmostEqual(op.peak_ma, (180.0 + 0.428) / 1.0367, places=9)
        self.assertGreater(op.mj_unc, 0)

    def test_windows(self):
        s = self.log.seconds
        e, n = energy.window_energy_mj(s, 1.5, 3.5)   # seconds ending 2.5 and 3.5
        self.assertEqual(n, 2)
        self.assertAlmostEqual(e, s[1].power_mw + s[2].power_mw)
        ab, _ = energy.above_baseline_mj(s, 1.5, 3.5, 500.0)
        self.assertAlmostEqual(ab, e - 1000.0)

    def test_no_prefix_counts_seconds(self):
        fd, p = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(line.split("] ", 1)[1] for line in SAMPLE.splitlines()) + "\n")
        log = energy.parse(p)
        os.remove(p)
        self.assertFalse(log.host_time)
        self.assertEqual([x.t for x in log.seconds], [1.0, 2.0, 3.0, 4.0])


if __name__ == "__main__":
    unittest.main()
