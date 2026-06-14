#!/usr/bin/env python3
"""
Convert ELF binary to C array
"""
import sys
import os

def elf_to_c(elf_path, c_output, h_output, var_name):
    """Convert ELF binary to C source and header"""

    with open(elf_path, 'rb') as f:
        data = f.read()

    # Write C source file
    with open(c_output, 'w') as f:
        f.write("/*============================================================================= \n")
        f.write(" * SECURITY FIX (AUDIT 5): W^X Violation - Enforce Read-Only ELF Data \n")
        f.write(" *============================================================================= \n")
        f.write(" * Making embedded ELF read-only to prevent code modification attacks. \n")
        f.write(" *===========================================================================*/ \n")
        f.write("\n")
        f.write(f"const unsigned char {var_name}[] = {{\n")

        # Write data in rows of 12 bytes
        for i in range(0, len(data), 12):
            chunk = data[i:i+12]
            hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
            f.write(f"  {hex_bytes},\n")

        f.write("};\n")
        f.write(f"const unsigned int {var_name}_len = {len(data)};\n")

    # Write header file
    with open(h_output, 'w') as f:
        f.write("#pragma once\n")
        f.write("\n")
        guard_name = os.path.basename(h_output).upper().replace('.', '_')
        comment = f"Embedded {os.path.basename(elf_path)} ELF executable"
        if "signed" in elf_path:
            comment += " (ECDSA signed)"
        f.write(f"/* {comment} */\n")
        f.write(f"extern const unsigned char {var_name}[];\n")
        f.write(f"extern const unsigned int {var_name}_len;\n")

    print(f"[+] Converted {elf_path} -> {c_output}, {h_output}")
    print(f"    Size: {len(data)} bytes")

def main():
    if len(sys.argv) < 5:
        print("Usage: elf_to_c.py <input.elf> <output.c> <output.h> <var_name>")
        print("")
        print("Example:")
        print("  elf_to_c.py hello.elf.signed hello_elf_data.c hello_elf_data.h hello_elf_data")
        sys.exit(1)

    elf_path = sys.argv[1]
    c_output = sys.argv[2]
    h_output = sys.argv[3]
    var_name = sys.argv[4]

    if not os.path.exists(elf_path):
        print(f"ERROR: Input file not found: {elf_path}")
        sys.exit(1)

    elf_to_c(elf_path, c_output, h_output, var_name)

if __name__ == '__main__':
    main()
