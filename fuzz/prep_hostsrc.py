#!/usr/bin/env python3
"""Copy src/ into a host-buildable tree for the fuzz targets.

The kernel is i386 freestanding C; the fuzz targets run on the build host
(arm64 or x86_64, 64-bit). Three mechanical rewrites make that possible, all
applied to the COPY -- src/ is never modified:

1. fuzz/shim/*.h replace headers that are nothing but i386 asm wrappers.
2. Every remaining `__asm__ volatile(...)` / `asm volatile(...)` statement is
   elided to `((void)0)`. Outputs are left untouched, so code that reads one
   (net_current_cpl's %cs, elf.c's saved CR3) sees an indeterminate value;
   none of the fuzzed parsers branch on those.
3. Physical-page allocator calls that round-trip a pointer through uint32_t
   (`(uint8_t*)pmm_alloc()`) are routed to fuzz_page_alloc(), which returns a
   real host pointer. A 64-bit host cannot map memory below 4 GB (arm64 macOS
   kills binaries with a small __PAGEZERO), so the truncating cast would
   otherwise fault on the first page.

Usage: prep_hostsrc.py <src_dir> <shim_dir> <out_dir>
"""
import os
import re
import shutil
import sys

ASM_RE = re.compile(rb"\b(__asm__|asm)\s+(volatile|__volatile__)?\s*\(")

PMM_REWRITES = [
    (re.compile(rb"\(\s*(\w+)\s*\*\s*\)\s*pmm_alloc\s*\(\s*\)"),
     rb"(\1*)fuzz_page_alloc()"),
    (re.compile(rb"pmm_free\s*\(\s*\(\s*uint32_t\s*\)\s*"), rb"fuzz_page_free((void*)"),
]


def elide_asm(text):
    out = bytearray()
    pos = 0
    while True:
        m = ASM_RE.search(text, pos)
        if not m:
            out += text[pos:]
            return bytes(out)
        out += text[pos:m.start()]
        depth = 1
        i = m.end()
        in_str = False
        while i < len(text) and depth:
            c = text[i:i + 1]
            if in_str:
                if c == b"\\":
                    i += 1
                elif c == b'"':
                    in_str = False
            elif c == b'"':
                in_str = True
            elif c == b"(":
                depth += 1
            elif c == b")":
                depth -= 1
            i += 1
        out += b"((void)0)"
        pos = i


def main():
    src, shim, dst = sys.argv[1:4]
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    shims = set(os.listdir(shim))
    for name in os.listdir(src):
        if not name.endswith((".c", ".h")):
            continue
        if name in shims:
            shutil.copy(os.path.join(shim, name), os.path.join(dst, name))
            continue
        with open(os.path.join(src, name), "rb") as f:
            text = f.read()
        text = elide_asm(text)
        for rx, rep in PMM_REWRITES:
            text = rx.sub(rep, text)
        with open(os.path.join(dst, name), "wb") as f:
            f.write(text)
    # Shims for headers that do not exist in src/ (none today) still get copied.
    for name in shims - set(os.listdir(dst)):
        shutil.copy(os.path.join(shim, name), os.path.join(dst, name))


if __name__ == "__main__":
    main()
