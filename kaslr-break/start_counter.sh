#! /bin/sh

sudo modprobe msr

# PAGE_WALKS.CYCLES (on goldmont)
EVENT_SEL=0x05
UMASK=0x03

# 16: USR
# 17: OS
# 21: AnyThread (include measurements in sibling HT)
# 22: Enable
VAL="$(($EVENT_SEL | ($UMASK << 8) | (1 << 22) | (1 << 16) | (1 << 17)|(1 << 21)))"
printf '[+] Writing 0x%X to IA32_PERFEVTSEL0 (186H)\n' $VAL
# IA32_PERFEVTSEL0 MSR (0x186)
sudo wrmsr -a 0x186 $VAL

# IA32_PERF_GLOBAL_CTRL (38FH) enable PMC0
sudo wrmsr -a 0x38f 0x1
