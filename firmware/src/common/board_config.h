#pragma once
// Shared pin map for the 2 real nodes (field_node, gateway — BOM in brief
// v2 section 11 has 2x of each sensor/indicator, not 3; the attacker node
// doesn't get an OLED/LED/buzzer/tamper sensors). Adjust to match actual
// wiring once boards arrive; these are reasonable ESP32-WROOM-32 devkit
// defaults.

#include <cstdint>

namespace sentinel::board {

// I2C bus (LCD backpack + MPU6050 share it)
constexpr int I2C_SDA = 21;
constexpr int I2C_SCL = 22;
// The BOM's "OLED" turned out, on the actual hardware in hand, to be a 16x2
// character LCD behind an I2C backpack (not a real graphical SSD1306/SH1106
// OLED) -- confirmed during bring-up on both field_node and gateway.
// LiquidCrystal_I2C is used against this address instead of Adafruit_SSD1306.
constexpr uint8_t LCD_I2C_ADDR = 0x27; // the other common backpack address is 0x3F
constexpr int LCD_COLS = 16;
constexpr int LCD_ROWS = 2;

// Tamper sensing — brief v2 section 10 lists 4 independent sensors:
// light (LDR), accelerometer (MPU6050), magnetic reed switch, and voltage.
// Reed switch is deliberately a second, independent channel for the same
// "case opened" event as the LDR (defends against covering the LDR).
constexpr int PIN_LDR = 34;                 // analog, case-opened light sensor
constexpr int LDR_TAMPER_THRESHOLD = 2500;  // ADC counts, tune once wired
constexpr int PIN_REED_SWITCH = 27;         // digital, active-low (closed=LOW=case shut)
constexpr float VOLTAGE_ANOMALY_DELTA_V = 0.3f; // sudden jump/drop vs rolling baseline -> tamper

// RGB status LED (common-cathode assumed; invert if common-anode).
// Brief v2 section 10: green=secure, yellow=degraded crypto/weak link,
// steady red=network attack, flashing red=physical tamper.
constexpr int PIN_LED_R = 25;
constexpr int PIN_LED_G = 26;
constexpr int PIN_LED_B = 13;   // moved off pin 27, now used by the reed switch

// Buzzer
constexpr int PIN_BUZZER = 33;

// Buttons
constexpr int PIN_BTN_URGENT = 32;  // field node: forces a fresh ML-KEM-1024 handshake (brief v2 section 8)
constexpr int PIN_BTN_AUX = 35;     // field node: demo "debug button" that cuts TX power to
                                     // simulate a weak link (brief v2 section 12, opt beat) —
                                     // input-only pin on WROOM-32, fine since it's read-only

// Battery: 18650 on 5V shield, 100k/100k divider halves Vbat onto this ADC pin.
constexpr int PIN_BATTERY_ADC = 39;
constexpr float BATTERY_DIVIDER_RATIO = 2.0f; // Vbat = ADC_volts * this
constexpr float BATTERY_FULL_V = 4.2f;
constexpr float BATTERY_EMPTY_V = 3.3f;

// v4 energy rig (docs/v4_energy_split.md): GPIO marker line between the
// board under test (src/benchmark or the field node) and the Monitor
// board's INA219 rig (src/monitor). The board under test raises this pin
// for the duration of each measured operation; the Monitor board watches
// it as an input and attributes INA219 samples in between to that
// operation. Same GPIO number on both boards, joined by a single jumper.
constexpr int PIN_ENERGY_MARKER = 4;
constexpr uint8_t INA219_I2C_ADDR = 0x40; // Adafruit INA219 default address

// Serial link to console (gateway only): USB serial, 115200 8N1, one
// message (EVT/TRC/LOG in, LABEL out) per line, per contract.
constexpr uint32_t CONSOLE_SERIAL_BAUD = 115200;

} // namespace sentinel::board
