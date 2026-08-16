#!/usr/bin/env python3
"""Inject raw Ethernet frames onto a QEMU socket-netdev multicast group.

Used by verify-rxdrop-counters.sh to produce frames with an EtherType TinyOS
does not handle. QEMU's user-mode NAT cannot carry an arbitrary EtherType --
by the time the host stack emits a UDP datagram the EtherType is 0x0800 -- so
the guest is attached to a `socket,mcast=` netdev instead, where whatever bytes
are written to the group appear on the guest's wire verbatim.

This needs no root: it is an ordinary UDP multicast socket, not AF_PACKET. The
harness's root check exists for other injection modes and is deliberately
conservative.
"""

import argparse
import socket
import struct
import sys


def parse_mac(text):
    parts = text.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC must be six colon-separated octets")
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError("MAC octets must be hex")


def build_frame(dst_mac, src_mac, ethertype, payload_len):
    """A minimum-size Ethernet frame with the given EtherType.

    Padded to 60 bytes (the on-wire minimum excluding FCS) so the frame is not
    treated as a runt by anything in the path -- this test is about the
    EtherType dispatch arm, and a short frame would be dropped one check
    earlier, incrementing a different counter and quietly testing nothing.
    """
    header = dst_mac + src_mac + struct.pack("!H", ethertype)
    body = bytes(payload_len)
    frame = header + body
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mcast", required=True, help="group:port, e.g. 230.0.0.1:1234")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--ethertype", required=True,
                    help="EtherType, e.g. 0x88b5")
    ap.add_argument("--dst", type=parse_mac, required=True,
                    help="destination MAC (the guest)")
    ap.add_argument("--src", type=parse_mac, default=parse_mac("52:54:00:aa:bb:cc"),
                    help="source MAC")
    ap.add_argument("--payload-len", type=int, default=46)
    args = ap.parse_args()

    try:
        group, port_text = args.mcast.rsplit(":", 1)
        port = int(port_text)
    except ValueError:
        sys.exit("--mcast must be group:port")

    ethertype = int(args.ethertype, 0)
    if not 0 <= ethertype <= 0xFFFF:
        sys.exit("--ethertype out of range")

    frame = build_frame(args.dst, args.src, ethertype, args.payload_len)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # TTL 1: the frames must not escape the host. This is deliberately not
    # configurable -- a harness that leaks malformed frames onto a real network
    # is a problem regardless of what it is testing.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    try:
        for _ in range(args.count):
            sock.sendto(frame, (group, port))
    finally:
        sock.close()

    print(f"sent {args.count} frames, ethertype 0x{ethertype:04x}, {len(frame)} bytes each")


if __name__ == "__main__":
    main()
