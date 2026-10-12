#ifdef ARDUINO
#include "common/crypto_task.h"
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

namespace sentinel {

namespace {
struct Job { CryptoJob fn; void* arg; };
QueueHandle_t g_q = nullptr;
TaskHandle_t g_task = nullptr;
StaticTask_t g_tcb;
StackType_t* g_stack = nullptr;
size_t g_stack_bytes = 0;
volatile bool g_busy = false;

void task_main(void*) {
    for (;;) {
        Job j;
        if (xQueueReceive(g_q, &j, portMAX_DELAY) == pdTRUE) {
            j.fn(j.arg);
            g_busy = false;
        }
    }
}
} // namespace

bool crypto_task_start(size_t stack_bytes, int core) {
    g_q = xQueueCreate(1, sizeof(Job));
    g_stack = static_cast<StackType_t*>(heap_caps_malloc(stack_bytes, MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL));
    if (!g_q || !g_stack) {
        Serial.printf("LOG crypto_task: cannot allocate %u B stack (largest free block %u B)\n",
                      static_cast<unsigned>(stack_bytes),
                      static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)));
        return false;
    }
    g_stack_bytes = stack_bytes;
    // On ESP32 StackType_t is a byte, so the depth argument is in bytes.
    g_task = xTaskCreateStaticPinnedToCore(task_main, "pqc", static_cast<uint32_t>(stack_bytes), nullptr,
                                           2, g_stack, &g_tcb, core);
    if (!g_task) {
        Serial.println("LOG crypto_task: xTaskCreateStaticPinnedToCore failed");
        return false;
    }
    Serial.printf("LOG crypto_task: %u B stack on core %d\n", static_cast<unsigned>(stack_bytes), core);
    return true;
}

bool crypto_task_submit(CryptoJob fn, void* arg) {
    if (!g_q || g_busy) return false;
    Job j{fn, arg};
    g_busy = true;
    if (xQueueSend(g_q, &j, 0) != pdTRUE) {
        g_busy = false;
        return false;
    }
    return true;
}

bool crypto_task_busy() { return g_busy; }
size_t crypto_task_stack_size() { return g_stack_bytes; }
uint32_t crypto_task_stack_free_min() {
    return g_task ? static_cast<uint32_t>(uxTaskGetStackHighWaterMark(g_task)) : 0;
}

} // namespace sentinel
#endif // ARDUINO
