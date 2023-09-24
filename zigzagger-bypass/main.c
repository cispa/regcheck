/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>

#include "cacheutils.h"

#define ITERATIONS 100000
#define REPS 1000
#define HISTOGRAM_ENTRIES 100
#define HISTOGRAM_SCALE 1
#define MEASUREMENTS 1000
#define HISTS 3
#define LOGFILE "histogram.csv"

#define SPACING 512
#define LEAKAGE_FAILED ((uint64_t)-1)

__attribute__((aligned(4096))) char mem[8][SPACING * 300];
int init = 0;

void init_leak_pmc()
{
  memset(mem, 1, sizeof(mem));
  CACHE_MISS = detect_flush_reload_threshold() + 10;
  init = 1;
}

__attribute__((aligned(4096)))
uint64_t
leak_pmc()
{
  if (!init)
  {
    printf("[!] Call init_leak_pmc() first!\n");
    exit(1);
  }

  int i, j;
  for (j = 0; j < 8; j++)
  {
    for (i = 0; i < 256; i++)
    {
      flush(mem[j] + i * SPACING);
    }
  }
  asm volatile("mfence");

  signal(SIGSEGV, trycatch_segfault_handler);

  for (size_t iterations = 0; iterations < 5; iterations++)
  {
    uint64_t low = 0, high = 0, try = 0;
    size_t start = rdtsc();

    do
    {
      for (int rep = 0; rep < 1; rep++)
      {
        if (!setjmp(trycatch_buf))
        {
          asm volatile("cpuid"
                       :
                       : "a"(0), "b"(0), "c"(0), "d"(0)
                       : "memory");
          asm volatile("imul %%rcx, %%rcx\n"
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
              :
              : "a"(low), "d"(high), "c"(&mem[3]), "b"(&mem[4]), [mem2] "r"(&mem[2]), [mem1] "r"(&mem[1])
              : "memory", "r11", "r12");

          try_abort();
        }
      }

      int hits = 0;
      uint64_t recovered = 0;
      int bytes_to_leak = 4;
      for (j = 1; j < 5; j++)
      {
        for (i = 1; i < 255; i++)
        {
          size_t idx = ((i * 167u) + 13u) & 255u;
          size_t delta = flush_reload_t(mem[j] + idx * SPACING);
          if (delta < CACHE_MISS)
          {
            recovered |= idx * ((uint64_t)1 << (j * 8));
            hits++;
            break;
          }
        }
      }
      if (hits == bytes_to_leak)
      {
        return recovered;
      }

      try++;
    } while (try < 50);

    size_t end = rdtsc();
    return LEAKAGE_FAILED;
  }
}

// see asm.S
extern void zigzag_bench(int nb, int a, int b);

void *get_zz_adrs(void)
{
  return zigzag_bench;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
  int ret;
  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                group_fd, flags);
  return ret;
}

uint64_t test_zigzagger_nospec(int fd, int a, int b, int iterations)
{
  long long count = 0;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  zigzag_bench(iterations, a, b);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  read(fd, &count, sizeof(count));
  return (uint64_t)count / iterations;
}

uint64_t test_zigzagger_spec(int a, int b, int iterations)
{
  uint64_t before = leak_pmc();
  zigzag_bench(iterations, a, b);
  uint64_t after = leak_pmc();
  return before == LEAKAGE_FAILED || after == LEAKAGE_FAILED ? LEAKAGE_FAILED : (after - before) /iterations;
}


size_t hists_spec[HISTS][HISTOGRAM_ENTRIES];
size_t hists_nospec[HISTS][HISTOGRAM_ENTRIES];

void measure_hist_spec(size_t *hist, int a, int b, int iter, size_t reps)
{
  size_t i = 0;
  while( i < reps){
    uint64_t res = test_zigzagger_spec(a, b, iter);
    if (res != LEAKAGE_FAILED){
      if(res < HISTOGRAM_ENTRIES){
        hist[res]++;
      }
      i++;
    }
  }
}

void measure_hist_nospec(size_t *hist, int a, int b, int iter, size_t reps, int fd)

{
  for (size_t i = 0; i < reps; i++)
  {
    uint64_t res = test_zigzagger_nospec(fd, a, b, iter);
    if (res < HISTOGRAM_ENTRIES)
      hist[res]++;
  }
}


int main(int argc, char** argv)
{
#ifdef TEST_NOSPEC
  struct perf_event_attr pe;
  long long count;
  int fd;

  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_HW_INSTRUCTIONS;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;

  fd = perf_event_open(&pe, 0, -1, -1, 0);
  if (fd == -1)
  {
    fprintf(stderr, "Error opening leader %llx\n", pe.config);
    exit(EXIT_FAILURE);
  }

  measure_hist_nospec(hists_nospec[0], 0, 0, ITERATIONS, REPS,fd);
  measure_hist_nospec(hists_nospec[1], 0, 1, ITERATIONS, REPS,fd);
  measure_hist_nospec(hists_nospec[2], 1, 0, ITERATIONS, REPS,fd);
  close(fd);

  FILE *logfile = fopen(LOGFILE, "w+");
  if (logfile == NULL)
  {
    fprintf(stderr, "Error: Could not open logfile: %s\n", LOGFILE);
    return -1;
  }

  fprintf(logfile, "Retired,Arg1,Arg2,Arg3\n");

  for (size_t i = 0; i < HISTOGRAM_ENTRIES; i += HISTOGRAM_SCALE)
  {
    size_t sums[HISTS];
    memset(sums, 0, sizeof(sums));
    for (size_t scale = 0; scale < HISTOGRAM_SCALE; scale++)
    {
      for (int h = 0; h < HISTS; h++)
      {
        sums[h] += hists_nospec[h][i + scale];
      }
    }
    fprintf(stdout, "%4zu: ", i);
    for (int h = 0; h < HISTS; h++)
    {
      fprintf(stdout, "%10zu ", sums[h]);
    }
    printf("\n");
    if (logfile != NULL)
    {
      fprintf(logfile, "%zu", i);
      for (int h = 0; h < HISTS; h++)
      {
        fprintf(logfile, ",%zu", sums[h]);
      }
      fprintf(logfile, "\n");
    }
  }
  fclose(logfile);
#else

  FILE *logfile = fopen(LOGFILE, "w+");
  if (logfile == NULL)
  {
    fprintf(stderr, "Error: Could not open logfile: %s\n", LOGFILE);
    return -1;
  }

  fprintf(logfile, "Retired,Arg1,Arg2,Arg3\n");

  init_leak_pmc();
  measure_hist_spec(hists_spec[0], 0, 0, ITERATIONS, REPS);
  measure_hist_spec(hists_spec[1], 0, 1, ITERATIONS, REPS);
  measure_hist_spec(hists_spec[2], 1, 0, ITERATIONS, REPS);

  for (size_t i = 0; i < HISTOGRAM_ENTRIES; i += HISTOGRAM_SCALE)
  {
    size_t sums[HISTS];
    memset(sums, 0, sizeof(sums));
    for (size_t scale = 0; scale < HISTOGRAM_SCALE; scale++)
    {
      for (int h = 0; h < HISTS; h++)
      {
        sums[h] += hists_spec[h][i + scale];
      }
    }
    fprintf(stdout, "%4zu: ", i);
    for (int h = 0; h < HISTS; h++)
    {
      fprintf(stdout, "%10zu ", sums[h]);
    }
    printf("\n");
    if (logfile != NULL)
    {
      fprintf(logfile, "%zu", i);
      for (int h = 0; h < HISTS; h++)
      {
        fprintf(logfile, ",%zu", sums[h]);
      }
      fprintf(logfile, "\n");
    }
  }
  fclose(logfile);
#endif
}
