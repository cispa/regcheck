# RegCheck

This folder contains the code of RegCheck, a tool to search for system register leakage based on the Meltdown 3a (Meltdown-CPL-REG) vulnerability.
The code is designed to run on Ubuntu 20.04 and 22.04. It is unlikely to work out-of-the-box on other distributions.

## DISCLAIMER
The scripts `checker_init.py` and `checker_cleanup.py` **tamper with your system configuration**.
Therefore we highly recommend that you use this tool **only on a test system and not on a productive system**.

## Build
Just run `make`.

## Testing Your System
**ATTENTION:** Read the above disclaimer.

1) Execute either `python3 checker_init.py` or `python3 checker_init.py microcode`. The later version will additionally try to update the microcode on the system to make sure it is up to date. Afterwards, both calls will change the kernel parameters to denoise the system and disable unprivileged access to certain system registers.
2) Restart the system.
3) Start `./run.sh` to execute the leakage tests for the system registers.
4) Execute `python3 checker_cleanup.py`
5) Restart the system.
