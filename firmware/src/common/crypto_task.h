#pragma once
// A dedicated FreeRTOS task with a LARGE stack for the post-quantum work.
// ML-DSA signing needs far more stack than the Arduino loop task has (the E1
// benchmark found ML-DSA-65 needs a task stack in the ~64-94 kB range; see
// paper/data/E1). The stack is taken from the heap at the very start of
// setup(), BEFORE Wi-Fi is initialised, because Wi-Fi fragments the heap and a
// 90 kB contiguous block may no longer exist afterwards.
//
// One job at a time ("single slot"): while a handshake is being computed, new
// admissions are refused and counted. That bounds the victim's crypto work and
// memory, and it is a deliberate, documented design choice.

#include <cstddef>
#include <cstdint>

namespace sentinel {

using CryptoJob = void (*)(void* arg);

// Call once, first thing in setup(). Returns false (and logs why) if the stack
// block could not be allocated.
bool crypto_task_start(size_t stack_bytes, int core);
// Queues a job. Returns false if a job is already running or queued.
bool crypto_task_submit(CryptoJob fn, void* arg);
bool crypto_task_busy();
// Smallest amount of stack ever left free in the task, in bytes.
uint32_t crypto_task_stack_free_min();
size_t crypto_task_stack_size();

} // namespace sentinel
