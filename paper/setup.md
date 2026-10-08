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

## Calibration (fill after Phase 4)
| Load | Multimeter | Sensor | Error % |
|---|---|---|---|
| open | | | |
| 22 ohm | | | |
| 10 ohm | | | |

## Versions (fill in)
- `pio --version`: ___ | espressif32 platform: ___ | Arduino-ESP32 core: ___
- Python ___ | gcc ___
- PQClean commit: 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (vendored 2026-10-08)
- Firmware commit used for each run: see `runlog.csv`
