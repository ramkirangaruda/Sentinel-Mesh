#include "common/mesh_transport.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_idf_version.h>
#include <cstring>

// ESP-NOW's receive-callback signature changed between Arduino-ESP32 core
// versions (core 3.x / ESP-IDF 5.x carries a real esp_now_recv_info_t with
// RSSI; core 2.x / ESP-IDF 4.x only hands back a bare MAC address, no
// RSSI). ESP_IDF_VERSION_MAJOR lets this file compile correctly either way
// without the person building it needing to know or care which core they
// have installed.

namespace sentinel::mesh {

namespace {

RecvCallback g_user_callback = nullptr;
constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

} // namespace

#if ESP_IDF_VERSION_MAJOR >= 5
static void on_esp_now_recv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    if (!g_user_callback || len <= 0) return;
    int rssi = (info && info->rx_ctrl) ? info->rx_ctrl->rssi : -50;
    g_user_callback(data, static_cast<size_t>(len), rssi);
}
#else
// No RSSI available on this older API -- -50 is a documented placeholder.
// It only affects the weak-link RSSI heuristic's precision, not whether
// packets are sent/received/decoded correctly.
static void on_esp_now_recv(const uint8_t* mac_addr, const uint8_t* data, int len) {
    (void)mac_addr;
    if (!g_user_callback || len <= 0) return;
    g_user_callback(data, static_cast<size_t>(len), -50);
}
#endif

bool init(RecvCallback on_recv) {
    g_user_callback = on_recv;

    Serial.println("LOG mesh: init() start");
    WiFi.mode(WIFI_STA);
    Serial.println("LOG mesh: WiFi.mode(WIFI_STA) done");
    WiFi.disconnect(); // ESP-NOW needs the radio up, not associated to an AP
    Serial.println("LOG mesh: WiFi.disconnect() done");

    if (esp_now_init() != ESP_OK) {
        Serial.println("LOG mesh: esp_now_init() failed");
        return false;
    }
    Serial.println("LOG mesh: esp_now_init() done");

    esp_now_register_recv_cb(on_esp_now_recv);
    Serial.println("LOG mesh: esp_now_register_recv_cb() done");

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = 0; // current channel
    peer.encrypt = false;
    if (esp_now_add_peer(&peer) != ESP_OK) {
        Serial.println("LOG mesh: esp_now_add_peer(broadcast) failed");
        return false;
    }
    Serial.println("LOG mesh: esp_now_add_peer() done");

    Serial.printf("LOG mesh: ESP-NOW ready (broadcast mode), MAC=%s\n",
                  WiFi.macAddress().c_str());
    return true;
}

bool broadcast(const uint8_t* data, size_t len) {
    esp_err_t err = esp_now_send(BROADCAST_MAC, data, len);
    if (err != ESP_OK) {
        Serial.printf("LOG mesh: esp_now_send failed, err=%d\n", static_cast<int>(err));
        return false;
    }
    return true;
}

} // namespace sentinel::mesh
