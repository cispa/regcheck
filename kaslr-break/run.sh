#! /bin/sh

sudo taskset -c 1 ./start_counter.sh
taskset -c 1 ./kaslr
