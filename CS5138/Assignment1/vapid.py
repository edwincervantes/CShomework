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
        print("{} is not a valid path".format(vap_args[1]))
        flag = False
    # Check if hex then check if decimal
    if not is_hex(vap_args[2][2:]):
        print("Not a valid hexidecimal, checking for decimal...")
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


def get_sections(pe, image_base):
    section_dir = {}
    for section in pe.sections:
        rva_addr = hex(section.VirtualAddress)
        va_addr = hex(int(rva_addr, 16) + int(image_base, 16))
        val = []
        val.append(rva_addr)
        val.append(va_addr)
        val.append(hex(section.PointerToRawData))
        section_dir[section.Name.decode("utf-8").replace("\x00", "")] = val
    return section_dir


def get_target_section(sections, target_virtual_addr):
    target_section = ''
    pos = 0
    for key in sections:
        pos = pos + 1
        curr = sections[key][1]
        if int(target_virtual_addr, 16) > int(curr, 16):
            target_section = key
    if target_section == '':
        print('{} --> ???'.format(target_virtual_addr))
        exit(1)
    else:
        return target_section


def get_offset_target_section(sections, target_section, target_virtual_addr):
    start_va = sections[target_section][1]
    return hex(int(target_virtual_addr, 16) - int(start_va, 16))
    

def get_physical_start(sections, offset_target_section, target_section):
    physical_section_start = sections[target_section][2]
    print(target_section)
    return hex(int(physical_section_start, 16) + int(offset_target_section, 16))



if __name__ == "__main__":
    # Get the total number of args passed to the demo.py
    vapid_args = list(sys.argv)

    if not valid_args(vapid_args):
        exit(1)

    exe_path = vapid_args[1]
    target_virtual_addr = vapid_args[2]
    pe = pefile.PE(exe_path)

    if not check_32bit(pe):
        print("{} must be a 32-bit .exe")

    addr_of_entry_point = get_entry_point(pe)   # Get entry point
    image_base = get_image_base(pe)     # Get image base
    sections = get_sections(pe, image_base)     # Create dictionary of sections in the format 'key:[rva, va, physical]'
    target_section = get_target_section(sections, target_virtual_addr)     # Get target section and address
    offset_target_section = get_offset_target_section(sections, target_section, target_virtual_addr)    # Get offset into the target section
    rva_physical = get_physical_start(sections, offset_target_section, target_section)      # Add offset to the start of the section on disk
    print("Physical Location: {}".format(rva_physical))
else:
    print("Whoops")
    exit(1)
