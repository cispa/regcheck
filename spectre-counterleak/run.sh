#! /bin/sh

sudo taskset -c 1 ./start_counter.sh
make
taskset -c 1 ./spectre
sudo taskset -c 1 ./stop_counter.sh
