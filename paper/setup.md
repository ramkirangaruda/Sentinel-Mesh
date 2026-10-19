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
Do NOT put 22 ohm or 10 ohm across 5 V (1.1 W and 2.5 W: they overheat). Loads redesigned 2026-10-19 for the ROBOLARK ¼ W 5 % carbon-film kit (no 2 W parts available): every
resistor sits alone across 5 V in parallel, so each is at most 5.16^2/270 = 0.10 W (under half its rating); the kit's 220 ohm packet was missing. Use the loads below; compute the
reference current as I = V/R from the multimeter (volts across the load, ohms with power off), not an ammeter.
Zero offset measured 2026-10-15 with Vin+/Vin- open: -0.30 mA (shunt -0.03 mV, steady to +/-0.01 mA), 989 samples/s.

| Load | Multimeter (V, R, I=V/R) | Sensor `current_ma` (minus offset) | Error % |
|---|---|---|---|
| open | n/a | -0.30 mA (offset) | |
| L1: 1x 1 kohm (about 5 mA) | | | |
| L2: 1x 270 ohm (about 19 mA) | | | |
| L3: 3x 270 ohm in parallel (about 57 mA) | | | |
| L4: 5x 270 ohm in parallel (about 96 mA) | | | |
| L5: 5x 270 + 5x 330 ohm, all in parallel (about 174 mA) | | | |
| L6: 5x 270 + 5x 330 + 5x 390 ohm, all in parallel (about 240 mA) | | | |

## Versions (fill in)
- `pio --version`: ___ | espressif32 platform: ___ | Arduino-ESP32 core: ___
- Python ___ | gcc ___
- Build check 2026-10-18 (Chaitanya's laptop, all 17 ESP32 envs): `pio` 6.2.0 | espressif32 7.1.3 |
  framework-arduinoespressif32 4.20017.260907 (sha dcc1105b) | Python 3.12.10 | gcc 14.2.0 (MSYS2, host tests).
  `platformio.ini` does not pin the platform version, so the flashing laptop may resolve a different one: record
  that laptop's versions here too before the energy runs (copy the `PLATFORM:` line from any `pio run`).
- PQClean commit: 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (vendored 2026-10-08)
- Firmware commit used for each run: see `runlog.csv`
