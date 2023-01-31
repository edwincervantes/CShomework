#!/bin/python3
# Edwin Cervantes
# Assignment 1 - Vapid
# Run PyLint before turning in
import sys
import os


def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def valid_args(vap_args):
    flag = True
    # We use 3 because vapid is counted as an arg during execution
    if len(vap_args) != 3:
        print("Incorrect number of arguments. Expected 2, and got {}".format(len(vap_args) - 1))
        flag = False
    if not os.path.exists(vap_args[1]):
        # Maybe we should check if it is an exe here or when we get the header info
        print("{} is not a valid path".format(vap_args[1]))
        flag = False
    # Check if hex then check if decimal
    if not is_hex(vap_args[2][2:]):
        if not int(vap_args[2]):
            print("The Target Virtual Address must be in hexadecimal form (0x1234) or decimal")
            flag = False
    return flag


def check_tva(tva):
    valid_tva = True

    return valid_tva


if __name__ == "__main__":
    # Get the total number of args passed to the demo.py
    vapid_args = list(sys.argv)
    if not valid_args(vapid_args):
        exit(1)
    exe_path = vapid_args[1]
    target_virtual_addr = vapid_args[2]
    if not check_tva(target_virtual_addr):
        print("{} -> ???".format(target_virtual_addr))

    # Get the arguments list

else:
    print("Whoops")
    exit(1)
