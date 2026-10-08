// SentinelMesh energy-rig firmware -- the "Monitor" ESP32 (brief v4 /
// docs/v4_energy_split.md, firmware task 1: "new src/monitor/main.cpp +
// platformio.ini env for the second ('Monitor') ESP32 -- current sensor
// over I2C, reads a GPIO marker the field node raises/lowers at each
// operation's start/end, attributes mJ per operation.").
//
// Sensor: ADS1115 precision ADC, swapped in for the INA219 this file
// originally targeted (team had an ADS1115 on hand instead). Unlike
// INA219, the ADS1115 has no built-in shunt amplifier and its inputs
// can't safely exceed its own 3.3V supply -- so unlike a typical INA219
// placement, **the shunt sits low-side**, in the battery's return/GND
// leg rather than the positive lead:
//
//   battery(+) ------------------------> shield(+) -> board under test
//   battery(-) --[shunt, board::SHUNT_RESISTANCE_OHMS]--> shield GND
//                     |                |
//                    A0               A1   (ADS1115 differential pair)
//
// Both A0 and A1 then sit within millivolts of true ground no matter the
// battery voltage -- safe for a 3.3V-powered ADS1115. Bus (battery)
// voltage is read separately on A2 through a divider (reuses
// board::BATTERY_DIVIDER_RATIO, the same 100k/100k pattern the field
// node already uses for its own battery ADC), since the ADS1115 can only
// see up to its own supply rail directly.
//
// Wiring: the shunt + divider sit in series with the board-under-test's
// supply (whichever board is running src/benchmark during a bench
// measurement, or the field node during a real deployment run); the
// ADS1115's I2C pins (SDA/SCL) go to this Monitor board. A single GPIO
// jumper (board::PIN_ENERGY_MARKER, same pin number on both boards)
// carries the marker: HIGH while a measured operation is in progress, LOW
// at rest. This board has no idea *what* operation is running -- it only
// knows a marked interval started and ended, and how many mJ and how much
// peak current passed during it. Correlate rows here with the matching
// src/benchmark CSV line by run order (start both captures together) or
// by hand-annotating the label at capture time.
//
// Covers, per docs/v4_energy_split.md task 1: ML-KEM keygen/encaps/decaps
// x3 levels, ML-DSA-44 sign/verify, AES-256-GCM per KB, radio handshake
// per level, idle/hourly baseline -- src/benchmark's job is to bracket
// each of those with the marker pin; this board just measures whatever
// interval it's shown.
//
// STATUS: structural, matches the rest of the firmware's "write code that
// compiles, not yet build-verified on hardware" state -- no ADS1115 board
// or second ESP32 available in the environment this was written in.

#include <Arduino.h>
#include <Wire.h>
#if defined(SENTINEL_SENSOR_INA219)
#include <Adafruit_INA219.h>
#else
#include <Adafruit_ADS1X15.h>
#endif
#include "common/board_config.h"

using namespace sentinel; // board:: lives in sentinel::board (common/board_config.h)

#if defined(SENTINEL_SENSOR_INA219)
// INA219 on the HIGH side of the field node's 5 V line (charger 5V -> Vin+, Vin- -> node VIN).
static Adafruit_INA219 g_ina(board::INA219_I2C_ADDR);
static bool g_ads_ok = false;   // name kept: "sensor ok"
#else
static Adafruit_ADS1115 g_ads;
static bool g_ads_ok = false;
#endif

// Battery voltage barely moves within one short crypto operation, so we
// don't need to re-read it every sample -- and we can't read both channels
// "at once" anyway (ADS1115 is single-channel-at-a-time: switching the mux
// costs a full conversion). Spending most samples on current only, and
// refreshing voltage every Nth sample, gets close to the ADS1115's max
// per-channel rate (860SPS, ~1.16ms/conversion) for the signal that
// actually needs the time resolution -- current during a short operation
// -- rather than splitting it evenly and getting ~430Hz on both.
constexpr int VOLTAGE_REFRESH_EVERY_N_SAMPLES = 10;
static float g_last_bus_v = 3.7f; // seed with a plausible resting Li-ion voltage until the first real read
static int g_sample_count = 0;

// ~1.2ms reflects the dominant single-channel (current) conversion time at
// the ADS1115's fastest data rate; the occasional extra voltage conversion
// makes the true average a bit slower than this -- documented so real
// hardware isn't "surprised" that this lands under ~800Hz average rather
// than the INA219 version's ~1kHz.
#if defined(SENTINEL_SENSOR_INA219)
constexpr uint32_t SAMPLE_INTERVAL_US = 1000;
#else
constexpr uint32_t SAMPLE_INTERVAL_US = 1200;
#endif

static bool g_marker_active = false;
static uint32_t g_interval_start_us = 0;
static double g_interval_energy_uj = 0.0; // accumulated over the current marked interval
static float g_interval_peak_ma = 0.0f;
static uint32_t g_op_index = 0;
static uint32_t g_last_sample_us = 0;

// v4: continuous telemetry for the console's battery chart -- one
// `NRG <json>` line per second (contracts/CONTRACT.md "Serial lines",
// contracts/energy.schema.json), alongside the per-operation CSV above.
// Without it the console's power/battery charts have no real data.
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

#if defined(SENTINEL_SENSOR_INA219)
static void sample_ina219(double dt_s) {
    if (!g_ads_ok) return;
    float current_ma = g_ina.getCurrent_mA();
    float bus_v = g_ina.getBusVoltage_V();
    float power_mw = bus_v * current_ma;
    g_last_bus_v = bus_v;
    g_nrg_energy_mj += static_cast<double>(power_mw) * dt_s;
    g_nrg_seconds += dt_s;
    g_last_load_v = bus_v;
    g_last_current_ma = current_ma;
    if (g_marker_active) {
        g_interval_energy_uj += static_cast<double>(power_mw) * dt_s * 1000.0;
        if (current_ma > g_interval_peak_ma) g_interval_peak_ma = current_ma;
    }
}
#else
// Reads the low-side shunt (A0-A1 differential) every call for the best
// achievable time resolution on current; only re-reads bus voltage (A2,
// through the divider) every VOLTAGE_REFRESH_EVERY_N_SAMPLES-th call and
// reuses the last value otherwise -- see the file header for why.
static void sample_ads1115(double dt_s) {
    if (!g_ads_ok) return;

    g_ads.setGain(GAIN_SIXTEEN); // +-256mV full-scale: best resolution for a small shunt drop
    int16_t shunt_raw = g_ads.readADC_Differential_0_1();
    float shunt_v = g_ads.computeVolts(shunt_raw);
    float current_ma = (shunt_v / board::SHUNT_RESISTANCE_OHMS) * 1000.0f;

    if (g_sample_count % VOLTAGE_REFRESH_EVERY_N_SAMPLES == 0) {
        g_ads.setGain(GAIN_ONE); // +-4.096V: covers the divided battery voltage with margin
        int16_t bus_raw = g_ads.readADC_SingleEnded(2);
        g_last_bus_v = g_ads.computeVolts(bus_raw) * board::BATTERY_DIVIDER_RATIO;
    }
    g_sample_count++;

    float power_mw = g_last_bus_v * current_ma; // V * mA = mW

    g_nrg_energy_mj += static_cast<double>(power_mw) * dt_s;
    g_nrg_seconds += dt_s;
    g_last_load_v = g_last_bus_v; // low-side shunt: the battery terminal voltage is the load voltage to within millivolts
    g_last_current_ma = current_ma;

    if (g_marker_active) {
        g_interval_energy_uj += static_cast<double>(power_mw) * dt_s * 1000.0; // mW*s = mJ, *1000 -> uJ
        if (current_ma > g_interval_peak_ma) g_interval_peak_ma = current_ma;
    }
}

#endif // !SENTINEL_SENSOR_INA219

// Battery % from the cell voltage. A2 reads the cell directly through the
// divider (see the file header), so the voltage here is the cell's. An
// estimate -- voltage sags under load -- which is why battery_pct is optional
// in the schema.
static float battery_pct_from_volts(float v) {
    float pct = (v - board::BATTERY_EMPTY_V) / (board::BATTERY_FULL_V - board::BATTERY_EMPTY_V) * 100.0f;
    if (pct < 0.0f) pct = 0.0f;
    if (pct > 100.0f) pct = 100.0f;
    return pct;
}

static void emit_nrg_line() {
    if (!g_ads_ok || g_nrg_seconds <= 0.0) return;
    double mean_mw = g_nrg_energy_mj / g_nrg_seconds;
    g_nrg_energy_mj = 0.0;
    g_nrg_seconds = 0.0;
    if (mean_mw < 0.0) {
        // Negative current usually means the shunt is wired backwards. The
        // schema rejects negative power, so say so instead of sending it.
        Serial.println("LOG monitor: negative power -- are the shunt's A0/A1 leads swapped?");
        return;
    }
    // ts is uptime millis(); the console swaps in arrival time (CONTRACT.md "Timestamps").
    Serial.printf("NRG {\"ts\":%lu,\"power_mw\":%.1f,\"volts\":%.3f,\"amps\":%.4f,\"battery_pct\":%.1f}\n",
                  static_cast<unsigned long>(millis()), mean_mw, static_cast<double>(g_last_load_v),
                  static_cast<double>(g_last_current_ma) / 1000.0,
                  static_cast<double>(battery_pct_from_volts(g_last_load_v)));
}

void setup() {
    Serial.begin(board::CONSOLE_SERIAL_BAUD);
    pinMode(board::PIN_ENERGY_MARKER, INPUT_PULLDOWN); // floating INPUT flooded serial with noise edges

    Wire.begin(board::I2C_SDA, board::I2C_SCL);
#if defined(SENTINEL_SENSOR_INA219)
    Wire.setClock(400000);
    g_ads_ok = g_ina.begin();
    if (g_ads_ok) {
        g_ina.setCalibration_32V_2A(); // 0.1 mA/bit, up to 3.2 A: covers any ESP32 burst
    } else {
        Serial.println("LOG monitor: INA219 not found on I2C bus");
    }
#else
    g_ads_ok = g_ads.begin(board::ADS1115_I2C_ADDR);
    if (g_ads_ok) {
        g_ads.setDataRate(RATE_ADS1115_860SPS); // fastest available -- default 128SPS is far too slow here
    } else {
        Serial.println("LOG monitor: ADS1115 not found on I2C bus");
    }
#endif

    Serial.println("LOG monitor boot complete");
    Serial.println("monitor,op,us,mJ,peak_current_mA");
    g_last_sample_us = micros();
    g_nrg_start_us = g_last_sample_us;
}

void loop() {
    uint32_t now_us = micros();
    if (now_us - g_last_sample_us >= SAMPLE_INTERVAL_US) {
        double dt_s = static_cast<double>(now_us - g_last_sample_us) / 1e6;
#if defined(SENTINEL_SENSOR_INA219)
        sample_ina219(dt_s);
#else
        sample_ads1115(dt_s);
#endif
        poll_marker(now_us);
        g_last_sample_us = now_us;
    }
    if (now_us - g_nrg_start_us >= NRG_INTERVAL_US) {
        emit_nrg_line();
        g_nrg_start_us = now_us;
    }
}
