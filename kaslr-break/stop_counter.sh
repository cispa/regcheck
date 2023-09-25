#! /bin/sh

sudo modprobe msr
# IA32_PERFEVTSEL0
sudo wrmsr -a 0x186 0x0
# IA32_PERF_GLOBAL_CTRL
sudo wrmsr -a 0x38f 0x0
