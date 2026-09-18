// SentinelMesh energy-rig firmware -- the "Monitor" ESP32 (brief v4 /
// docs/v4_energy_split.md, firmware task 1: "reads a GPIO marker the field
// node raises/lowers at each operation's start/end, attributes mJ per
// operation.").
//
// HARDWARE NOTE: the original design called for an INA219 current/voltage
// sensor, but the board actually in hand for this build is an ADS1115
// 16-bit ADC instead, reading current across a manually-built shunt (four
// 10-ohm resistors in parallel, measured/assumed ~2.5 ohms -- see
// docs/hardware_setup.md's bring-up notes) rather than an INA219's
// factory-calibrated internal shunt. This file was rewritten against that
// real hardware; the INA219-based version is what's in git history if a
// real INA219 ever replaces this rig.
//
// Wiring: the shunt sits in series with the raw battery lead, before the
// boost/charge shield (so shield conversion losses aren't counted in every
// energy number) -- ADS1115 channels A0/A1 read the differential voltage
// across it. If a battery-voltage divider is also wired (100k+100k into
// A2), this also reports load voltage and an estimated battery %; if not,
// voltage/battery_pct fields are omitted rather than reporting zero. A
// single GPIO jumper (board::PIN_ENERGY_MARKER, same pin number on both
// boards) carries the marker: HIGH while a measured operation is in
// progress, LOW at rest. This board has no idea *what* operation is
// running -- it only knows a marked interval started and ended, and how
// many mJ and how much peak current passed during it.
//
// SAMPLING RATE, honestly: the ADS1115 is not the INA219 -- it has one ADC
// multiplexed across channels, so reading both the shunt (differential,
// high gain) and the battery divider (single-ended, lower gain) means two
// conversions per cycle, each ~1.2ms at the fastest practical data rate.
// That's roughly 400Hz combined, not the ~1kHz the INA219 version assumed
// -- documented here so real hardware isn't "surprised" by the difference,
// same honesty-rule convention as the rest of this codebase.

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_ADS1X15.h>
#include "common/board_config.h"

using namespace sentinel; // board:: lives in sentinel::board (common/board_config.h)

// --- Hardware constants specific to this rig (not in board_config.h since
// they're this board's own sensor calibration, not a shared pin/protocol
// value like PIN_ENERGY_MARKER is). ---
constexpr uint8_t ADS1115_I2C_ADDR = 0x48;      // Adafruit ADS1115 default address
constexpr float SHUNT_OHMS = 2.5f;              // four 10-ohm resistors in parallel, measured during bring-up
constexpr float BATTERY_DIVIDER_RATIO = 2.0f;   // 100k+100k divider halves Vbat onto A2 -- Vbat = A2_volts * this

static Adafruit_ADS1115 g_ads;
static bool g_ads_ok = false;
static bool g_have_battery_divider = false; // set true once a real (non-zero-ish) A2 reading is seen

// Effective combined sample rate is lower than a single-channel figure
// would suggest -- see file header. This interval paces the *pair* of
// reads (shunt + battery), not either one alone.
constexpr uint32_t SAMPLE_INTERVAL_US = 2500; // ~400Hz combined, matches the ADS1115's real achievable rate

static bool g_marker_active = false;
static uint32_t g_interval_start_us = 0;
static double g_interval_energy_uj = 0.0; // accumulated over the current marked interval
static float g_interval_peak_ma = 0.0f;
static uint32_t g_op_index = 0;
static uint32_t g_last_sample_us = 0;

// v4: continuous telemetry for the console's battery chart -- one
// `NRG <json>` line per second (contracts/CONTRACT.md "Serial lines",
// contracts/energy.schema.json), alongside the per-operation CSV above.
constexpr uint32_t NRG_INTERVAL_US = 1000000;
static uint32_t g_nrg_start_us = 0;
static double g_nrg_energy_mj = 0.0;  // integral of power over the interval
static double g_nrg_seconds = 0.0;
static float g_last_load_v = 0.0f;
static float g_last_current_ma = 0.0f;

// Reports a completed interval. CSV columns extend the src/benchmark shape
// (algo,op,us,heap_used_bytes,stack_hwm_bytes,ok) with the two columns
// only this board can measure -- mJ and peak_current_mA -- prefixed with
// a running op_index instead of an algo/op name, since this board can't
// see which operation the board under test thinks it's running.
static void report_interval(uint32_t duration_us) {
    double mj = g_interval_energy_uj / 1000.0; // accumulated in micro-joules -> milli-joules
    Serial.printf("monitor,op_%lu,%lu,%.3f,%.2f\n",
                  static_cast<unsigned long>(g_op_index),
                  static_cast<unsigned long>(duration_us),
                  mj, static_cast<double>(g_interval_peak_ma));
    g_op_index++;
}

static void poll_marker(uint32_t now_us) {
    bool marker = digitalRead(board::PIN_ENERGY_MARKER) == HIGH;
    if (marker && !g_marker_active) {
        // Rising edge: a new measured operation started.
        g_marker_active = true;
        g_interval_start_us = now_us;
        g_interval_energy_uj = 0.0;
        g_interval_peak_ma = 0.0f;
    } else if (!marker && g_marker_active) {
        // Falling edge: it ended.
        g_marker_active = false;
        report_interval(now_us - g_interval_start_us);
    }
}

// Reads the shunt (differential A0-A1, high gain for a small voltage) and,
// if wired, the battery divider (single-ended A2, lower gain for a larger
// voltage). Two separate gain settings mean two separate conversions --
// this is the reason for this board's slower combined sample rate.
static void sample_ads1115(double dt_s) {
    if (!g_ads_ok) return;

    g_ads.setGain(GAIN_SIXTEEN); // +-256mV range -- shunt drop is small
    int16_t shunt_raw = g_ads.readADC_Differential_0_1();
    float shunt_v = g_ads.computeVolts(shunt_raw);
    float current_ma = (shunt_v / SHUNT_OHMS) * 1000.0f;
    // A negative reading just means the shunt's two leads are swapped --
    // report the magnitude rather than a confusing negative current, same
    // spirit as the INA219 version's own "wired backwards" check below.
    if (current_ma < 0) current_ma = -current_ma;

    g_ads.setGain(GAIN_ONE); // +-4.096V range -- fine for a halved battery voltage
    int16_t batt_raw = g_ads.readADC_SingleEnded(2);
    float batt_adc_v = g_ads.computeVolts(batt_raw);
    float load_v = batt_adc_v * BATTERY_DIVIDER_RATIO;
    // A real divider reads a real battery voltage (a few volts); near-zero
    // means A2 isn't actually wired to anything -- don't report a fake 0V.
    g_have_battery_divider = load_v > 0.5f;

    float power_mw = g_have_battery_divider ? (load_v * current_ma) : 0.0f;

    if (g_have_battery_divider) {
        g_nrg_energy_mj += static_cast<double>(power_mw) * dt_s;
        g_nrg_seconds += dt_s;
        g_last_load_v = load_v;
    }
    g_last_current_ma = current_ma;

    if (g_marker_active && g_have_battery_divider) {
        g_interval_energy_uj += static_cast<double>(power_mw) * dt_s * 1000.0; // mW*s = mJ, *1000 -> uJ
    }
    if (g_marker_active && current_ma > g_interval_peak_ma) {
        g_interval_peak_ma = current_ma;
    }
}

// Battery % from the cell voltage. An estimate -- voltage sags under load
// -- which is why battery_pct is optional in the schema.
static float battery_pct_from_volts(float v) {
    float pct = (v - board::BATTERY_EMPTY_V) / (board::BATTERY_FULL_V - board::BATTERY_EMPTY_V) * 100.0f;
    if (pct < 0.0f) pct = 0.0f;
    if (pct > 100.0f) pct = 100.0f;
    return pct;
}

static void emit_nrg_line() {
    if (!g_ads_ok) return;
    if (!g_have_battery_divider || g_nrg_seconds <= 0.0) {
        // No divider wired -- still worth a line so the console/log shows
        // this board is alive and measuring current, just without power/
        // voltage/battery figures it has no real data for.
        Serial.printf("NRG {\"ts\":%lu,\"amps\":%.4f}\n",
                      static_cast<unsigned long>(millis()),
                      static_cast<double>(g_last_current_ma) / 1000.0);
        return;
    }
    double mean_mw = g_nrg_energy_mj / g_nrg_seconds;
    g_nrg_energy_mj = 0.0;
    g_nrg_seconds = 0.0;
    // ts is uptime millis(); the console swaps in arrival time (CONTRACT.md "Timestamps").
    Serial.printf("NRG {\"ts\":%lu,\"power_mw\":%.1f,\"volts\":%.3f,\"amps\":%.4f,\"battery_pct\":%.1f}\n",
                  static_cast<unsigned long>(millis()), mean_mw, static_cast<double>(g_last_load_v),
                  static_cast<double>(g_last_current_ma) / 1000.0,
                  static_cast<double>(battery_pct_from_volts(g_last_load_v)));
}

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    pinMode(board::PIN_ENERGY_MARKER, INPUT);

    Wire.begin(board::I2C_SDA, board::I2C_SCL);
    g_ads_ok = g_ads.begin(ADS1115_I2C_ADDR);
    if (g_ads_ok) {
        g_ads.setDataRate(RATE_ADS1115_860SPS); // fastest available; still ~2 conversions/cycle, see header
    } else {
        Serial.println("LOG monitor: ADS1115 not found on I2C bus");
    }

    Serial.println("LOG monitor boot complete (ADS1115 + manual shunt rig)");
    Serial.println("monitor,op,us,mJ,peak_current_mA");
    g_last_sample_us = micros();
    g_nrg_start_us = g_last_sample_us;
}

void loop() {
    uint32_t now_us = micros();
    if (now_us - g_last_sample_us >= SAMPLE_INTERVAL_US) {
        double dt_s = static_cast<double>(now_us - g_last_sample_us) / 1e6;
        sample_ads1115(dt_s);
        poll_marker(now_us);
        g_last_sample_us = now_us;
    }
    if (now_us - g_nrg_start_us >= NRG_INTERVAL_US) {
        emit_nrg_line();
        g_nrg_start_us = now_us;
    }
}
