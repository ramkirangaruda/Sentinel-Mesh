# Setup record (team fills in; reviewers read this)

## Hardware actually in hand (as of 2026-10-08)
- ESP32 boards: ___ x ESP32-WROOM-32 (exact model/seller: ___)
- Board a4:f0:0f:77:a2:70: ESP32-D0WD-V3 rev v3.1, 40 MHz crystal, CP2102 USB bridge (first benchmarked 2026-10-08, COM6)
- Current sensor: ADS1115 + ~2.5 ohm shunt (rehearsal only, `env:monitor`); INA219 ordered for the paper rig (`env:monitor_ina219`)
- Battery: none yet
- Display: 16x2 LCD with HW-61 I2C backpack (I2C address found by scanner: ___)
- Other: buzzer module, RGB LEDs, resistors

## Known problems with the current rig (see execution guide / chat notes)
- ADS1115 gain x16 with a 2.5 ohm shunt saturates at about 102 mA (256 mV / 2.5 ohm). ESP32 with radio on exceeds this.
- Low-side shunt lifts the field node's ground by I x R (about 0.25 V at 100 mA); marker wire reference shifts.
- No battery: `battery_pct` feature and E4 run-down impossible until one is added.
- LCD/LEDs/buzzer must be disconnected for every energy experiment (and firmware built with -DSENTINEL_MEASUREMENT_BUILD).
- Resolved by INA219: clipping and ground lift. SHUNT_RESISTANCE_OHMS in board_config.h now defaults to 2.5 (was 0.1) and only matters for the ADS1115 rehearsal; set it to your multimeter reading.

## Power supply for the rig
- Ve-Pro AC/DC adapter, label "OUTPUT: DC 5Volt 2A", centre-positive symbol, not marked "regulated", Mfg Jun 26.
  Plug is the small yellow-tipped barrel (likely 4.0 x 1.7 mm; a screw-terminal adapter must match that size).
- No-load voltage measured 2026-10-18 (HAOYUE DT830D, V DC 20 V range, red in centre, black on sleeve):
  **+5.16 V**, centre positive. Within the 4.8-5.3 V safe window.

## Calibration (fill after Phase 4)
Do NOT put 22 ohm or 10 ohm across 5 V (1.1 W and 2.5 W: they overheat). Loads redesigned 2026-10-21: only 1 kohm and 270 ohm ¼ W parts (15x 270, 5x 1k bought for this; kit returned): every
resistor sits alone across 5 V in parallel, so each is at most 5.16^2/270 = 0.10 W (under half its rating). Use the loads below; compute the
reference current as I = V/R from the multimeter (volts across the load, ohms with power off), not an ammeter.
Resistors measured 2026-10-21 (DT830D, Ω 2000 range, cold): 1 kohm metal film (blue) 988 and 989 ohm; 270 ohm carbon
film (beige, larger temperature drift) 263-269 ohm across 13 parts. Each load's total R is measured as built.
Zero offset measured 2026-10-15 with Vin+/Vin- open: -0.30 mA (shunt -0.03 mV, steady to +/-0.01 mA), 989 samples/s.

**Session 2, 2026-10-24 (the calibration used for the paper).** New test leads (0.6 ohm, subtracted from every R);
each load's R measured in place with the INA219 disconnected, V measured on a resistor's legs with the load running
30 s; sensor = 20 s mean of M's `LOG cal current_ma`. Warm R equalled cold R at L5 (no heating drift).
Raw: `paper/data/calibration.csv` (labels `S2 ...`) and `paper/data/calibration_raw_20261024_*.log`.
Fit: `python paper/analysis/calibration_fit.py`.

| Load | Multimeter V | Multimeter R (minus 0.6 lead) | Reference I = V/R | INA219 raw | INA219 bus V | Corrected | Residual |
|---|---|---|---|---|---|---|---|
| zero (5 V on, no load) | - | - | 0 | -0.203 mA | 5.232 | 0.217 mA | - |
| L1: 1x 1 kohm | 5.15 | 987.4 | 5.216 mA | 5.160 mA | 5.223 | 5.390 mA | +3.33 % (+0.17 mA) |
| L2: 1x 270 ohm | 5.12 | 265.4 | 19.292 mA | 19.744 mA | 5.203 | 19.457 mA | +0.85 % |
| L3: 3x 270 ohm | 5.06 | 87.7 | 57.697 mA | 59.144 mA | 5.147 | 57.460 mA | -0.41 % |
| L4: 5x 270 ohm | 5.00 | 52.7 | 94.877 mA | 97.398 mA | 5.092 | 94.358 mA | -0.55 % |
| L5: 10x 270 ohm | 4.84 | 26.5 | 182.642 mA | 188.671 mA | 4.967 | 182.396 mA | -0.13 % |
| L6: 13x 270 ohm | 4.74 | 20.4 | 232.353 mA | 240.926 mA | 4.889 | 232.799 mA | +0.19 % |

**Result:** INA219 current = **1.0367 x reference - 0.428 mA** (least squares over the 7 points). Against the DT830D the
INA219 reads **+3.67 %** high. After correcting with that line, every load from 57 to 232 mA (the ESP32's working
range) agrees within **0.6 %**; below 20 mA the residual is about +0.17 mA (3 % at 5 mA), so treat sub-20 mA
readings as +/-0.2 mA. Apply the correction in analysis (`(raw - (-0.428)) / 1.0367`); firmware and raw logs stay
uncorrected.

**Voltage:** the INA219 bus voltage reads 1.4 % above the DT830D at 5 mA, growing to 3.1 % at 232 mA. The growing
part is a real drop of about 0.3 ohm in the VIN- jumper and breadboard contacts between the sensor and the load;
the constant ~1.4 % is a disagreement between the two instruments.

**Which instrument is right is not settled.** Both gaps point the same way (the DT830D reads lower), so part of the
+3.67 % may be the meter, not the sensor. Before quoting absolute joules (claim C1), check L1 and L6 once against a
better meter (e.g. a calibrated bench multimeter in a college lab). Ratios (claim C2, victim J per attacker J) do not
depend on this gain.

Session 1 (2026-10-21) is a **trial run, excluded**: its black test lead was failing (it later broke), which inflated
the low resistances; two rows also had the VIN- jumper unseated (sensor saw no current).

## Versions (fill in)
- `pio --version`: ___ | espressif32 platform: ___ | Arduino-ESP32 core: ___
- Python ___ | gcc ___
- Build check 2026-10-18 (Chaitanya's laptop, all 17 ESP32 envs): `pio` 6.2.0 | espressif32 7.1.3 |
  framework-arduinoespressif32 4.20017.260907 (sha dcc1105b) | Python 3.12.10 | gcc 14.2.0 (MSYS2, host tests).
  `platformio.ini` does not pin the platform version, so the flashing laptop may resolve a different one: record
  that laptop's versions here too before the energy runs (copy the `PLATFORM:` line from any `pio run`).
- PQClean commit: 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (vendored 2026-10-08)
- Firmware commit used for each run: see `runlog.csv`
