#! /usr/bin/env python3

import os
import shutil

GRUB_CONFIG_STORE = "./grub_before_checker.bac"
GRUB_FILE = "/etc/default/grub"


def restore_grub_config():
    shutil.copyfile(GRUB_CONFIG_STORE, GRUB_FILE)


def update_grub():
    os.system("sudo update-grub")


def main():
    if os.geteuid() != 0:
        print("Gimme root pls *sweat smile*")
        return 1
    restore_grub_config()
    update_grub()
    print("Please restart the system.")


if __name__ == "__main__":
    main()
