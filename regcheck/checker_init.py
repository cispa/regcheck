#! /usr/bin/env python3


import os
import sys
import shutil
import subprocess
import platform

GRUB_CONFIG_STORE = "./grub_before_checker.bac"
GRUB_FILE = "/etc/default/grub"
NEW_PARAMS = "quit splash nosmep nosmap nofsgsbase nmi_watchdog=0 isolcpus=1"


def store_grub_config():
    shutil.copyfile(GRUB_FILE, GRUB_CONFIG_STORE)


def update_grub():
    os.system("sudo update-grub")

def switch_kernel_params(new_params):
    with open(GRUB_FILE, "r") as fd:
        lines_old = fd.readlines()
    lines_new = []
    replaced = False
    for line_old in lines_old:
        if line_old.startswith('GRUB_CMDLINE_LINUX_DEFAULT=\"'):
            line_new = f'GRUB_CMDLINE_LINUX_DEFAULT="{new_params}"\n'
            lines_new.append(line_new)
            replaced = True
        else:
            lines_new.append(line_old)
    if not replaced:
        print("Couldn't fine LINUX_DEFAULT line in ", GRUB_FILE)
        raise EnvironmentError

    with open(GRUB_FILE, "w") as fd:
        for line_new in lines_new:
            fd.write(line_new)

def install_dependencies():
    os.system("sudo apt-get install -y msr-tools")

def is_intel_cpu():
    cpuinfo = "".join(open("/proc/cpuinfo").readlines())
    return "Intel" in cpuinfo

def is_amd_cpu():
    cpuinfo = "".join(open("/proc/cpuinfo").readlines())
    return "AMD" in cpuinfo



def update_microcode_if_possible():
    os.system("sudo apt-get update")
    if is_intel_cpu():
        assert not is_amd_cpu()
        os.system("sudo apt-get install -y intel-microcode")
    elif is_amd_cpu():
        assert not is_intel_cpu()
        os.system("sudo apt-get install -y amd64-microcode")
    else:
        print("[ERR]: Could not detect CPU vendor")
        exit(1)

def main():
    if os.geteuid() != 0:
        print("Gimme root pls *sweat smile*")
        return 1
    install_dependencies()
    if sys.argv[1] == "microcode":
        update_microcode_if_possible()

    store_grub_config()
    switch_kernel_params(NEW_PARAMS)
    update_grub()
    print("Please restart the system and continue by executing 'sudo taskset -c 1 "
          "./checker_meltdown3a'")


if __name__ == "__main__":
    main()
