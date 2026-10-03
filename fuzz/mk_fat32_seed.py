#!/usr/bin/env python3
"""Write the fat32 target's seed: a tiny, valid FAT32 image.

512-byte sectors, 1 sector/cluster, 2 reserved sectors, one 1-sector FAT,
40 data clusters (2..41). Layout:
  /HELLO.TXT        600 bytes, clusters 3-4
  /SUB/             cluster 5
  /SUB/A.TXT        "longname.txt" via one LFN entry, 20 bytes, cluster 6
Free space is left for the harness's create/mkdir/write script.

Usage: mk_fat32_seed.py <out>
"""
import struct
import sys

SEC = 512
RESERVED, NFATS, FATSZ, DATA_CLUSTERS = 2, 1, 1, 40
TOTAL = RESERVED + NFATS * FATSZ + DATA_CLUSTERS
EOC = 0x0FFFFFFF


def dirent(name83, attr, cluster, size):
    return struct.pack("<11sBBBHHHHHHHI", name83, attr, 0, 0, 0, 0, 0,
                       cluster >> 16, 0, 0, cluster & 0xFFFF, size)


def lfn_checksum(name83):
    s = 0
    for c in name83:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def lfn(seq, name, name83):
    chars = [ord(c) for c in name] + [0]
    chars += [0xFFFF] * (13 - len(chars))
    u = lambda xs: b"".join(struct.pack("<H", x) for x in xs)
    return (bytes([seq | 0x40]) + u(chars[0:5]) + bytes([0x0F, 0, lfn_checksum(name83)])
            + u(chars[5:11]) + b"\0\0" + u(chars[11:13]))


def main():
    img = bytearray(TOTAL * SEC)
    bs = struct.pack("<3s8sHBHBHHBHHHII", b"\xEB\x58\x90", b"TINYOS  ", SEC, 1,
                     RESERVED, NFATS, 0, 0, 0xF8, 0, 0, 0, 0, TOTAL)
    bs += struct.pack("<IHHIHH12sBBBI11s8s", FATSZ, 0, 0, 2, 1, 0, b"\0" * 12,
                      0x80, 0, 0x29, 0x1234, b"FUZZVOL    ", b"FAT32   ")
    img[0:len(bs)] = bs
    img[510:512] = b"\x55\xAA"

    fat = [0x0FFFFFF8, EOC, EOC, 4, EOC, EOC, EOC] + [0] * (SEC // 4 - 7)
    off = RESERVED * SEC
    img[off:off + SEC] = struct.pack("<%dI" % (SEC // 4), *fat)

    def cl(n):
        return (RESERVED + NFATS * FATSZ + (n - 2)) * SEC

    root = dirent(b"FUZZVOL    ", 0x08, 0, 0)
    root += dirent(b"HELLO   TXT", 0x20, 3, 600)
    root += dirent(b"SUB        ", 0x10, 5, 0)
    img[cl(2):cl(2) + len(root)] = root

    hello = (b"hello, fat32 " * 50)[:600]
    img[cl(3):cl(3) + 600] = hello

    sub = dirent(b".          ", 0x10, 5, 0) + dirent(b"..         ", 0x10, 0, 0)
    sub += lfn(1, "longname.txt", b"A       TXT")
    sub += dirent(b"A       TXT", 0x20, 6, 20)
    img[cl(5):cl(5) + len(sub)] = sub
    img[cl(6):cl(6) + 20] = b"twenty bytes of data"

    with open(sys.argv[1], "wb") as f:
        f.write(img)


if __name__ == "__main__":
    main()
