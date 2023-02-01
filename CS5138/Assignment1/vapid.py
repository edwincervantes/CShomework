#!/bin/python3
# Edwin Cervantes
# Assignment 1 - Vapid
# Run PyLint before turning in
import os
# Might require a pip install, https://bufferoverflows.net/exploring-pe-files-with-python/
import pefile
import sys


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


def check_32bit(pe):
    bits = True
    if not hex(pe.FILE_HEADER.Machine) == '0x14c':
        bits = False
    return bits


def get_entry_point(pe):
    return hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)


def get_image_base(pe):
    return hex(pe.OPTIONAL_HEADER.ImageBase)


def get_sections(pe, base_addr):
    section_dir = {}
    for section in pe.sections:
        print(hex(section.VirtualAddress), int(base_addr, 16))
        val = []
        val.append(hex(section.VirtualAddress))
        val.append(int(hex(section.VirtualAddress), 16) + int(base_addr, 16))
        val.append(section.SizeOfRawData)
        section_dir[section.Name.decode("utf-8").replace("\x00", "")] = val
    return section_dir


if __name__ == "__main__":
    # Get the total number of args passed to the demo.py
    vapid_args = list(sys.argv)

    if not valid_args(vapid_args):
        exit(1)

    exe_path = vapid_args[1]
    target_virtual_addr = vapid_args[2]
    pe = pefile.PE(exe_path)

    if not check_tva(target_virtual_addr):
        print("{} -> ???".format(target_virtual_addr))

    if not check_32bit(pe):
        print("{} must be a 32-bit .exe")

    addr_of_entry_point = get_entry_point(pe)
    image_base = get_image_base(pe)
    sections = get_sections(pe, image_base)
    print(sections['.text'])

else:
    print("Whoops")
    exit(1)
