#!/bin/python3
# Edwin Cervantes
# Assignment 1 - Vapid
import os
import pefile
import sys


def is_hex(s):
    """
    is_hex checks if a number is hexidecimal or not.

    :param s: String of a possible hex value
    :return: Bool 
    """ 
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def valid_args(vap_args):
    """
    valid_args checks if the arguments provided by the user are valid.
    We need a valid path the a PE file that exists, followed by a hex or decimal number representing the virtual address we want to check

    :param vapid_args: List of provided arguments
    :return: Bool 
    """ 
    flag = False
    # We use 3 because vapid is counted as an arg during execution
    if len(vap_args) != 3:
        print("Incorrect number of arguments. Expected 2, and got {}".format(len(vap_args) - 1))
        flag = False
    if not os.path.exists(vap_args[1]):
        print("{} is not a valid path".format(vap_args[1]))
        flag = False
    # Check if hex then check if decimal
    if (vap_args[2][:2] == '0x'):
 	   if is_hex(vap_args[2][2:]):
 	   	flag = True
    elif int(vap_args[2]):
        flag = True  
    if flag is False:
    	        print("The Target Virtual Address must be in hexadecimal form (0x1234) or decimal")
    return flag


def check_32bit(pe):
    """
    check_32bit checks if give .exe program is 32-bits or not.

    :param pe: An objected created by PEfile
    :return: Bool 
    """ 
    bits = True
    if not hex(pe.FILE_HEADER.Machine) == '0x14c':
        bits = False
    return bits


def get_image_base(pe):
    """
    get_image_base gets the image base

    :param pe: An objected created by PEfile
    :return: string hex representation of image base 
    """ 
    return hex(pe.OPTIONAL_HEADER.ImageBase)


def get_sections(pe, image_base):
    """
    get_sections Creates a dictionary of the PE sections

    :param pe: An objected created by PEfile
    :param iamge_base: String representation of the image base

    :return: dictionary in the format of {section: [rva, va, physical location, virtual size, terminal end]}
    """ 
    section_dir = {}
    for section in pe.sections:
        rva_addr = hex(section.VirtualAddress)
        va_addr = hex(int(rva_addr, 16) + int(image_base, 16))
        v_size = hex(section.Misc_VirtualSize)
        #r_size = hex(section.SizeOfRawData)
        phys_loc = hex(section.PointerToRawData)
        val = []
        val.append(rva_addr)
        val.append(va_addr)
        val.append(phys_loc)    # Physical location
        val.append(v_size)   # Virtual Size
        val.append(hex(int(v_size, 16) + int(rva_addr, 16)))    # Terminal end
        section_dir[section.Name.decode("utf-8").replace("\x00", "")] = val
    return section_dir


def get_target_section(sections, relative_target_addr, target_virtual_addr):
    """
    get_target_section Gets the target section of where our given address is

    :param sections: Dictionary of sections
    :param relative_target_addr: String representation of the relative virtual address of the target
    :param target_virtual_addr: String representation of the virtual address of the target

    :return: string of the target section
    """ 
    target_section = ''
    pos = 0
    for key in sections:
        pos = pos + 1
        curr = sections[key][0]
        terminal_end = sections[key][4]
        if int(relative_target_addr, 16) > int(curr, 16) and int(relative_target_addr, 16) < int(terminal_end, 16):
            target_section = key
    if target_section == '':
        print('{} -> ??'.format(target_virtual_addr))
        exit(1)
    else:
        return target_section


def get_offset_target_section(sections, target_section, target_virtual_addr):
    """
    get_offset_target_section Gets the offset of the target section

    :param sections: Dictionary of sections
    :param target section: String representation of the target section
    :param target_virtual_addr: String representation of the virtual address of the target

    :return: string hex representation of the offset
    """ 
    start_va = sections[target_section][1]
    return hex(int(target_virtual_addr, 16) - int(start_va, 16))
    

def get_physical(sections, offset_target_section, target_section):
    """
    get_physical Gets the physical address we are looking for to return

    :param sections: Dictionary of sections
    :param offset_target_section: Our amount we offset by
    :param target_section: String representation of the target section

    :return: string hex representation of the physical address we are looking for
    """ 
    physical_section_start = sections[target_section][2]
    return hex(int(physical_section_start, 16) + int(offset_target_section, 16))



if __name__ == "__main__":
    vapid_args = list(sys.argv)

    if not valid_args(vapid_args):      #   Make sure entered arguments are valid
        exit(1)

    exe_path = vapid_args[1]        # Program loaded into memory
    
    target_virtual_addr = vapid_args[2]     # Virtual Address provided by user

    target_virtual_addr = target_virtual_addr.lower()       # Must return answer in lowercase
    
    if not (vapid_args[2][:2] == '0x'):
        target_virtual_addr = (hex(int(target_virtual_addr)))       

    pe = pefile.PE(exe_path)

    if not check_32bit(pe):     
        print("{} must be a 32-bit .exe")       # Only works with a 32-bit PE
    
    image_base = get_image_base(pe)     # Get image base

    relative_target_addr = hex(int(target_virtual_addr, 16) - int(image_base, 16))      # User inputs absolute Value so we must convert

    sections = get_sections(pe, image_base)     # Create dictionary of sections in the format 'key:[rva, va, physical, virtual size, end of section]'

    target_section = get_target_section(sections,relative_target_addr, target_virtual_addr)     # Get target section and address
    
    offset_target_section = get_offset_target_section(sections, target_section, target_virtual_addr)    # Get offset into the target section
    
    rva_physical = get_physical(sections, offset_target_section, target_section)      # Add offset to the start of the section on disk
    
    print("{} -> {}".format(target_virtual_addr, rva_physical))     # Successfully found
    
else:
    print("Whoops")
    exit(1)
