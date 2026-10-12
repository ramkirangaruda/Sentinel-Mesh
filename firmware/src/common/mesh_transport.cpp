#include "common/mesh_transport.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_idf_version.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <cstring>

#ifndef SENTINEL_WIFI_CHANNEL
#define SENTINEL_WIFI_CHANNEL 1
#endif
#ifndef SENTINEL_RX_QUEUE_DEPTH
#define SENTINEL_RX_QUEUE_DEPTH 24
#endif
// 1 = use the promiscuous-mode RSSI trick (IDF 4.x). Set 0 to disable.
#ifndef SENTINEL_RSSI_SNIFFER
#define SENTINEL_RSSI_SNIFFER 1
#endif

namespace sentinel::mesh {

namespace {

constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

QueueHandle_t g_rx_queue = nullptr;
SemaphoreHandle_t g_tx_done = nullptr;
SemaphoreHandle_t g_tx_mutex = nullptr;   // two tasks may transmit (loop + crypto task)
volatile uint32_t g_rx_overflow = 0;
volatile uint32_t g_rssi_missing = 0;

// Tiny MAC -> RSSI table fed by the sniffer (3 nodes + margin).
struct RssiEntry { uint8_t mac[6]; int8_t rssi; uint32_t ms; bool used; };
constexpr int RSSI_SLOTS = 6;
RssiEntry g_rssi[RSSI_SLOTS];

void rssi_store(const uint8_t* mac, int rssi) {
    int free_slot = -1;
    for (int i = 0; i < RSSI_SLOTS; i++) {
        if (g_rssi[i].used && memcmp(g_rssi[i].mac, mac, 6) == 0) {
            g_rssi[i].rssi = static_cast<int8_t>(rssi);
            g_rssi[i].ms = millis();
            return;
        }
        if (!g_rssi[i].used && free_slot < 0) free_slot = i;
    }
    if (free_slot < 0) free_slot = 0; // table full: overwrite (never happens with 3 nodes)
    memcpy(g_rssi[free_slot].mac, mac, 6);
    g_rssi[free_slot].rssi = static_cast<int8_t>(rssi);
    g_rssi[free_slot].ms = millis();
    g_rssi[free_slot].used = true;
}

bool rssi_lookup(const uint8_t* mac, int8_t& out) {
    for (int i = 0; i < RSSI_SLOTS; i++) {
        if (g_rssi[i].used && memcmp(g_rssi[i].mac, mac, 6) == 0 && millis() - g_rssi[i].ms < 1000) {
            out = g_rssi[i].rssi;
            return true;
        }
    }
    return false;
}

#if SENTINEL_RSSI_SNIFFER
// ESP-NOW frames are 802.11 vendor-specific ACTION frames (frame control byte 0 = 0xD0).
// The sniffer sees them with rx_ctrl.rssi; addr2 (transmitter) is at offset 10.
void sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || buf == nullptr) return;
    const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
    if (pkt->rx_ctrl.sig_len < 24 || pkt->payload[0] != 0xD0) return;
    rssi_store(pkt->payload + 10, pkt->rx_ctrl.rssi);
}
#endif

void enqueue(const uint8_t* mac, const uint8_t* data, int len) {
    if (!g_rx_queue || len <= 0 || len > static_cast<int>(MAX_FRAME)) return;
    Frame f;
    memcpy(f.data, data, static_cast<size_t>(len));
    f.len = static_cast<uint8_t>(len);
    f.rx_ms = millis();
    int8_t r = 0;
    if (mac && rssi_lookup(mac, r)) {
        f.rssi = r;
        f.rssi_valid = true;
    } else {
        f.rssi = -50;
        f.rssi_valid = false;
        g_rssi_missing++;
    }
    if (xQueueSend(g_rx_queue, &f, 0) != pdTRUE) g_rx_overflow++;
}

#if ESP_IDF_VERSION_MAJOR >= 5
void on_recv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    enqueue(info ? info->src_addr : nullptr, data, len);
}
#else
void on_recv(const uint8_t* mac, const uint8_t* data, int len) {
    enqueue(mac, data, len);
}
#endif

#if ESP_IDF_VERSION_MAJOR >= 5
void on_sent(const wifi_tx_info_t*, esp_now_send_status_t) {
#else
void on_sent(const uint8_t*, esp_now_send_status_t) {
#endif
    if (g_tx_done) xSemaphoreGive(g_tx_done);
}

} // namespace

bool init() {
    g_rx_queue = xQueueCreate(SENTINEL_RX_QUEUE_DEPTH, sizeof(Frame));
    g_tx_done = xSemaphoreCreateBinary();
    g_tx_mutex = xSemaphoreCreateMutex();
    if (!g_rx_queue || !g_tx_done || !g_tx_mutex) {
        Serial.println("LOG mesh: queue/semaphore alloc failed");
        return false;
    }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(SENTINEL_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

    if (esp_now_init() != ESP_OK) {
        Serial.println("LOG mesh: esp_now_init failed");
        return false;
    }
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_sent);

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = 0; // current channel
    peer.encrypt = false;
    if (esp_now_add_peer(&peer) != ESP_OK) {
        Serial.println("LOG mesh: add broadcast peer failed");
        return false;
    }

    bool sniffer = false;
#if SENTINEL_RSSI_SNIFFER && ESP_IDF_VERSION_MAJOR < 5
    wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    if (esp_wifi_set_promiscuous_filter(&filt) == ESP_OK &&
        esp_wifi_set_promiscuous_rx_cb(&sniffer_cb) == ESP_OK &&
        esp_wifi_set_promiscuous(true) == ESP_OK) {
        sniffer = true;
    }
#endif
    Serial.printf("LOG mesh: ESP-NOW ready ch=%d mac=%s rssi_sniffer=%s\n", SENTINEL_WIFI_CHANNEL,
                  WiFi.macAddress().c_str(), sniffer ? "on" : "OFF(rssi=-50 placeholder)");
    return true;
}

bool poll(Frame& out) {
    return g_rx_queue && xQueueReceive(g_rx_queue, &out, 0) == pdTRUE;
}

bool broadcast(const uint8_t* data, size_t len) {
    if (len == 0 || len > MAX_FRAME || !g_tx_mutex) return false;
    xSemaphoreTake(g_tx_mutex, portMAX_DELAY);
    xSemaphoreTake(g_tx_done, 0); // clear a stale token
    bool ok = false;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        esp_err_t err = esp_now_send(BROADCAST_MAC, data, len);
        if (err == ESP_OK) {
            xSemaphoreTake(g_tx_done, pdMS_TO_TICKS(25));
            ok = true;
        } else {
            vTaskDelay(1); // send queue full: give the radio a tick
        }
    }
    xSemaphoreGive(g_tx_mutex);
    return ok;
}

uint32_t rx_overflow_count() { return g_rx_overflow; }
uint32_t rssi_missing_count() { return g_rssi_missing; }

} // namespace sentinel::mesh
