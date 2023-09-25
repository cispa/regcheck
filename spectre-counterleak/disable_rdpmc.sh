#! /bin/sh

# disable userspace rdpmc
echo 1 | sudo tee /sys/devices/cpu/rdpmc



