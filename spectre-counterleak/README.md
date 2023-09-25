# Spectre with CounterLeak

## System Setup
For this PoC, you need a system where the performance counters leak via Meltdown3a (Meltdown-CPL-REG).
Additionally, depending on your microarchitecture, you need to configure the performance counter keeping track of division events in `start_counter.sh`. The information about this counter can be found in Intel's performance counter documentation.

## Build and Run
Just execute `make`.
Afterwards, run the experiment using `./run.sh`.

Depending on your system, you may need to change the value of the macro `HIT_THRESHOLD` in `spectre.c`.
To debug the values provided by your system, you can enable the userspace access to `rdpmc` using `enable_rdpmc.sh` and uncomment the macro `ARCHITECTURAL`.

