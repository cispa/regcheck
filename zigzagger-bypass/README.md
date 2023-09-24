# Zigzagger Bypass

This folder contains a PoC for the Zigzagger bypass.

## Build
Run `start_counter.sh` to program the required performance counters.
Just run `make`.

## Bypass Zigzagger
To see the Zigzagger bypass results, you only need to execute `./main`.
You will end up with a histogram and a csv named `histogram.csv`, which lists the arguments to the `zigzagger()` function and the retired instructions. 