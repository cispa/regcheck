#! /bin/sh

sudo modprobe msr

# BR_INST_RETIRED.ALL_BRANCHES (on coffeelake)
#EVENT_SEL=0xc4
#UMASK=0x4

# BR_INST_RETIRED.ALL_BRANCHES (on goldmont-based/lab01)
#EVENT_SEL=0xc4
#UMASK=0x0

# BR_MISP_RETIRED.ALL_BRANCHES (on goldmont-based/lab01)
#EVENT_SEL=0xc5
#UMASK=0x0

# INST_RETIRED.ANY_P (on goldmount-based/lab01)
EVENT_SEL=0xC0
UMASK=0x00

VAL="$(($EVENT_SEL | ($UMASK << 8) | (1 << 22) | (1 << 16) | (0 << 17)))"
printf '[+] Writing 0x%X to IA32_PERFEVTSEL0 (186H)\n' $VAL
# IA32_PERFEVTSEL0 MSR (0x186)
sudo wrmsr -a 0x186 $VAL

# IA32_PERF_GLOBAL_CTRL (38FH) enable PMC0
sudo wrmsr -a 0x38f 0x1