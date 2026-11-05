#!/usr/bin/env python3
"""Parse the INA219 monitor's (M's) log and apply the session-2 calibration.

  python paper/analysis/energy.py LOG [LOG ...] [--seconds-csv out.csv] [--ops-csv out.csv]
                                  [--window T0 T1] [--baseline T0 T1]

Reads raw logs only (never edits them). Understands three line kinds from
firmware/src/monitor/main.cpp (env monitor_ina219):
  LOG cal n= shunt_mv= bus_v= current_ma= mean_mw=   once per second, MEAN of ~990 samples
  NRG {"ts","power_mw","volts","amps","battery_pct"} once per second, power is the mean,
                                                     volts/amps are the LAST sample only
  monitor,op_N,us,mJ,peak_current_mA                 one per marked interval (GPIO4 high)
Lines may carry run_flood_test.py's `[   12.34s] ` host-time prefix; calibrate.py raw
logs carry none (then seconds are counted 1, 2, 3 ... from the first per-second line).

Calibration (paper/setup.md, session 2, 2026-10-24; fit by calibration_fit.py):
  I_raw = GAIN * I_true + OFFSET_MA   ->   I_true = (I_raw - OFFSET_MA) / GAIN
Power and energy are corrected with the same line. The offset is a current, so it
needs the voltage and the duration: P_true = (P_raw - OFFSET_MA * V) / GAIN and
E_true = (E_raw - OFFSET_MA * V * t) / GAIN (mA * V * s = mJ). V is the INA219 bus
voltage, which is NOT corrected (see UNCERTAINTY below). Raw logs stay uncorrected.

Per-second power comes from the `LOG cal` line when present: it is a true mean, and
unlike NRG it is still printed when the mean is negative (the firmware suppresses
NRG lines with negative power, e.g. an open input). NRG is the fallback for builds
without the cal line.

battery_pct in NRG is derived from the bus voltage with Li-ion thresholds. On the
5 V adaptor rig it means nothing (it reads 100): there is no battery, so any
battery figure is SIMULATED.
"""
import argparse, csv, json, math, re, statistics, sys
from dataclasses import dataclass, field

# ---- calibration constants (paper/setup.md, session 2) -------------------------
GAIN = 1.0367          # INA219 reads 3.67 % high against the DT830D
OFFSET_MA = -0.428     # INA219 zero error, mA
FIT_RANGE_MA = (5.0, 235.0)   # loads the fit covers: L1 5.2 mA .. L6 232.4 mA, rounded out

# ---- uncertainty (stated in paper/setup.md) ------------------------------------
# Random/fit part: residuals after correction are within 0.6 % over 57-232 mA and
# about +0.17 mA below 20 mA, so the bound is max(0.2 mA, 0.6 % of I). It covers every
# session-2 residual (largest: 0.17 mA at 5 mA, 0.85 % = 0.16 mA at 19 mA, 0.55 % at 95 mA).
RESID_ABS_MA = 0.2
RESID_REL = 0.006
# Systematic parts, reported separately because they are the same sign for every
# reading and cancel in ratios (claim C2):
REF_GAIN_SYS_REL = 0.0367   # which instrument is right (INA219 or DT830D) is not settled
BUS_V_SYS_REL = (0.014, 0.031)  # INA219 bus V reads 1.4 % (5 mA) to 3.1 % (232 mA) above the DT830D
SAMPLE_PERIOD_S = 1.0 / 989     # M samples at ~989/s; a marked interval is +-1 sample long


def correct_current_ma(i_raw_ma):
    return (i_raw_ma - OFFSET_MA) / GAIN


def correct_power_mw(p_raw_mw, volts):
    return (p_raw_mw - OFFSET_MA * volts) / GAIN


def correct_energy_mj(e_raw_mj, seconds, volts):
    return (e_raw_mj - OFFSET_MA * volts * seconds) / GAIN


def current_uncertainty_ma(i_true_ma):
    """Fit-residual bound on a corrected current (random part only)."""
    return max(RESID_ABS_MA, RESID_REL * abs(i_true_ma))


def energy_uncertainty_mj(e_true_mj, seconds, volts):
    """Bound on a corrected interval energy: fit residual on its mean current plus one
    sample of timing (a marked interval starts and ends on a sample). Random part
    only; REF_GAIN_SYS_REL and BUS_V_SYS_REL are systematic and quoted separately."""
    if seconds <= 0 or volts <= 0:
        return float("nan")
    i_mean = e_true_mj / (volts * seconds)              # mJ / (V s) = mA
    fit = current_uncertainty_ma(i_mean) * volts * seconds
    timing = (e_true_mj / seconds) * SAMPLE_PERIOD_S    # mean power x one sample
    return fit + timing


def in_fit_range(i_true_ma):
    return FIT_RANGE_MA[0] <= i_true_ma <= FIT_RANGE_MA[1]


# ---- parsing --------------------------------------------------------------------
PREFIX = re.compile(r"^\[\s*(-?[\d.]+)s\]\s?")
CAL = re.compile(r"LOG cal n=(\d+) shunt_mv=(-?[\d.]+) bus_v=(-?[\d.]+) current_ma=(-?[\d.]+) mean_mw=(-?[\d.]+)")
NRG = re.compile(r"NRG (\{.*\})")
OP = re.compile(r"monitor,op_(\d+),(\d+),(-?[\d.]+),(-?[\d.]+)\s*$")


@dataclass
class Second:
    """One per-second reading, raw and corrected."""
    t: float              # host seconds (log prefix) or 1, 2, 3 ... when the log has none
    source: str           # "cal" (mean of n samples) or "nrg" (mean power, last-sample volts)
    bus_v: float
    current_ma_raw: float
    power_mw_raw: float
    n: int = 0
    device_ts_ms: int = None

    @property
    def current_ma(self):
        return correct_current_ma(self.current_ma_raw)

    @property
    def power_mw(self):
        return correct_power_mw(self.power_mw_raw, self.bus_v)


@dataclass
class Op:
    """One marked interval (`monitor,op_N` row), raw and corrected."""
    index: int
    us: int
    mj_raw: float
    peak_ma_raw: float
    t: float = None       # host seconds if the log has them
    bus_v: float = None   # bus voltage of the nearest per-second reading

    @property
    def seconds(self):
        return self.us / 1e6

    @property
    def mj(self):
        return correct_energy_mj(self.mj_raw, self.seconds, self.bus_v)

    @property
    def mj_unc(self):
        return energy_uncertainty_mj(self.mj, self.seconds, self.bus_v)

    @property
    def peak_ma(self):
        return correct_current_ma(self.peak_ma_raw)

    @property
    def mean_ma(self):
        return self.mj / (self.bus_v * self.seconds) if self.seconds > 0 else float("nan")


@dataclass
class MonitorLog:
    path: str
    seconds: list = field(default_factory=list)
    ops: list = field(default_factory=list)
    negative_power_lines: int = 0
    bad_lines: int = 0
    host_time: bool = False


def parse(path):
    """Parse one monitor log. A `LOG cal` line and the NRG line after it describe the
    same second (the firmware prints them together), so they become one Second."""
    log = MonitorLog(path)
    pending_cal = None   # cal line waiting to see whether an NRG line follows
    count = 0
    for raw in open(path, encoding="utf-8", errors="replace").read().replace("\r", "\n").split("\n"):
        m = PREFIX.match(raw)
        t_host = float(m[1]) if m else None
        line = raw[m.end():] if m else raw
        if m:
            log.host_time = True
        if (c := CAL.search(line)):
            count += 1
            pending_cal = Second(t=t_host if t_host is not None else float(count), source="cal",
                                 bus_v=float(c[3]), current_ma_raw=float(c[4]),
                                 power_mw_raw=float(c[5]), n=int(c[1]))
            log.seconds.append(pending_cal)
        elif (j := NRG.search(line)):
            try:
                d = json.loads(j[1])
            except ValueError:   # line cut by a serial glitch
                log.bad_lines += 1
                continue
            if pending_cal is not None:   # same second as the cal line just read
                pending_cal.device_ts_ms = d.get("ts")
                pending_cal = None
                continue
            count += 1
            log.seconds.append(Second(t=t_host if t_host is not None else float(count), source="nrg",
                                      bus_v=float(d["volts"]), current_ma_raw=1000.0 * float(d["amps"]),
                                      power_mw_raw=float(d["power_mw"]), device_ts_ms=d.get("ts")))
        elif "negative power" in line:
            log.negative_power_lines += 1
            pending_cal = None
        elif (o := OP.search(line)):
            log.ops.append(Op(index=int(o[1]), us=int(o[2]), mj_raw=float(o[3]),
                              peak_ma_raw=float(o[4]), t=t_host))
    _attach_voltage(log)
    return log


def _attach_voltage(log):
    """Give every op the bus voltage of the second it ended in: the first per-second
    reading at or after the op (a reading covers the second before it). Without host
    time, use the mean bus voltage of the whole log."""
    if not log.seconds:
        for op in log.ops:
            op.bus_v = float("nan")
        return
    if log.host_time:
        for op in log.ops:
            ref = op.t if op.t is not None else log.seconds[0].t
            op.bus_v = next((s.bus_v for s in log.seconds if s.t >= ref), log.seconds[-1].bus_v)
    else:   # no clock: fall back to the mean bus voltage of the whole log
        v = statistics.mean(s.bus_v for s in log.seconds)
        for op in log.ops:
            op.bus_v = v


# ---- window helpers (for E2 baselines and E5 attack windows) ---------------------
def in_window(seconds, t0, t1):
    """Per-second readings whose second [t-1, t] lies inside [t0, t1]. A line is printed
    at the END of its second, so its host time stamps the interval that just closed."""
    return [s for s in seconds if s.t - 1.0 >= t0 - 1e-9 and s.t <= t1 + 1e-9]


def mean_power_mw(seconds, t0=None, t1=None):
    xs = seconds if t0 is None else in_window(seconds, t0, t1)
    return statistics.mean(s.power_mw for s in xs) if xs else float("nan")


def window_energy_mj(seconds, t0=None, t1=None):
    """Corrected energy over whole seconds in the window (each reading is a 1 s mean)."""
    xs = seconds if t0 is None else in_window(seconds, t0, t1)
    return sum(s.power_mw for s in xs), len(xs)


def window_energy_unc_mj(seconds, t0=None, t1=None):
    xs = seconds if t0 is None else in_window(seconds, t0, t1)
    return sum(current_uncertainty_ma(s.current_ma) * s.bus_v for s in xs)


def above_baseline_mj(seconds, t0, t1, baseline_mw):
    """Energy in [t0, t1] above a constant baseline power (e.g. idle before the attack)."""
    e, n = window_energy_mj(seconds, t0, t1)
    return e - baseline_mw * n, n


# ---- CLI ------------------------------------------------------------------------
def _fmt(x, nd=3):
    return "" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def report(log, window=None, baseline=None):
    print(f"\n{log.path}")
    src = {s.source for s in log.seconds}
    print(f"  {len(log.seconds)} per-second readings (source: {', '.join(sorted(src)) or '-'}), "
          f"{len(log.ops)} marked ops, time base: {'host clock' if log.host_time else 'line count (1 s each)'}")
    if log.negative_power_lines:
        print(f"  {log.negative_power_lines} seconds had negative mean power (no NRG line; open input or no load)")
    if log.seconds:
        cur = [s.current_ma for s in log.seconds]
        v = [s.bus_v for s in log.seconds]
        e, n = window_energy_mj(log.seconds)
        print(f"  current corrected: mean {statistics.mean(cur):.3f} mA (min {min(cur):.3f}, max {max(cur):.3f}); "
              f"raw mean {statistics.mean(s.current_ma_raw for s in log.seconds):.3f} mA")
        print(f"  bus voltage (uncorrected): mean {statistics.mean(v):.3f} V")
        print(f"  power corrected: mean {mean_power_mw(log.seconds):.1f} mW; energy over {n} s: "
              f"{e / 1000:.3f} J +- {window_energy_unc_mj(log.seconds) / 1000:.3f} J (fit), "
              f"+- {100 * REF_GAIN_SYS_REL:.2f} % systematic (reference meter not settled)")
        out = [s for s in log.seconds if not in_fit_range(s.current_ma)]
        if out:
            print(f"  {len(out)} readings outside the calibrated {FIT_RANGE_MA[0]:.0f}-{FIT_RANGE_MA[1]:.0f} mA range")
    if baseline:
        b = mean_power_mw(log.seconds, *baseline)
        print(f"  baseline {baseline[0]}-{baseline[1]} s: {b:.1f} mW")
    if window:
        e, n = window_energy_mj(log.seconds, *window)
        line = f"  window {window[0]}-{window[1]} s: {e / 1000:.3f} J over {n} s"
        if baseline:
            ab, _ = above_baseline_mj(log.seconds, window[0], window[1], mean_power_mw(log.seconds, *baseline))
            line += f", {ab / 1000:.3f} J above baseline"
        print(line)
    if log.ops:
        print(f"  {'op':>5}{'us':>10}{'mJ raw':>10}{'mJ':>10}{'+-':>8}{'mean mA':>9}{'peak mA':>9}")
        for op in log.ops[:40]:
            print(f"  {op.index:>5}{op.us:>10}{op.mj_raw:>10.3f}{op.mj:>10.3f}{op.mj_unc:>8.3f}"
                  f"{op.mean_ma:>9.1f}{op.peak_ma:>9.1f}")
        if len(log.ops) > 40:
            print(f"  ... {len(log.ops) - 40} more (use --ops-csv)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--seconds-csv")
    ap.add_argument("--ops-csv")
    ap.add_argument("--window", nargs=2, type=float, metavar=("T0", "T1"), help="host seconds")
    ap.add_argument("--baseline", nargs=2, type=float, metavar=("T0", "T1"), help="host seconds")
    a = ap.parse_args(argv)
    logs = [parse(p) for p in a.logs]
    print(f"calibration: I_true = (I_raw {-OFFSET_MA:+.3f} mA) / {GAIN}  (paper/setup.md, session 2)")
    for log in logs:
        report(log, a.window, a.baseline)
    if a.seconds_csv:
        with open(a.seconds_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["log", "t_s", "source", "n", "device_ts_ms", "bus_v", "current_ma_raw", "current_ma",
                        "current_unc_ma", "power_mw_raw", "power_mw"])
            for log in logs:
                for s in log.seconds:
                    w.writerow([log.path, _fmt(s.t, 2), s.source, s.n, s.device_ts_ms or "", _fmt(s.bus_v),
                                _fmt(s.current_ma_raw), _fmt(s.current_ma), _fmt(current_uncertainty_ma(s.current_ma)),
                                _fmt(s.power_mw_raw, 2), _fmt(s.power_mw, 2)])
    if a.ops_csv:
        with open(a.ops_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["log", "op_index", "t_s", "us", "bus_v", "mj_raw", "mj", "mj_unc", "mean_ma",
                        "peak_ma_raw", "peak_ma"])
            for log in logs:
                for op in log.ops:
                    w.writerow([log.path, op.index, _fmt(op.t, 2), op.us, _fmt(op.bus_v), _fmt(op.mj_raw),
                                _fmt(op.mj, 4), _fmt(op.mj_unc, 4), _fmt(op.mean_ma, 2), _fmt(op.peak_ma_raw, 2),
                                _fmt(op.peak_ma, 2)])


if __name__ == "__main__":
    sys.exit(main())
