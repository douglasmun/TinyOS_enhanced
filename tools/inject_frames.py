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


def checksum16(data):
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_icmp_frame(dst_mac, src_mac, src_ip, dst_ip, icmp_type,
                     identifier, sequence, payload_len):
    """A well-formed Ethernet/IPv4/ICMP frame.

    Unlike build_frame() above, every layer here must actually validate: the
    ICMP counters under test live past the IP header checks in handle_packet,
    so a malformed IP header would be dropped earlier and the test would
    silently measure nothing. Both checksums are therefore computed for real.

    icmp_type 8 = Echo Request, 0 = Echo Reply. The reply case is the one that
    matters for the unthrottled-print finding (A1): TinyOS accepts it only if
    `identifier` matches its CSPRNG-chosen ping_identifier, which models an
    on-path attacker who has observed one outbound ping.
    """
    payload = bytes(range(payload_len % 256)) [:payload_len] if payload_len else b""
    if len(payload) < payload_len:
        payload = (payload * (payload_len // max(len(payload), 1) + 1))[:payload_len]

    icmp = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload
    icmp = icmp[:2] + struct.pack("!H", checksum16(icmp)) + icmp[4:]

    total_len = 20 + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0x00, total_len,
                     0x1234, 0x0000,
                     64, 1, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

    frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + icmp
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mcast", required=True, help="group:port, e.g. 230.0.0.1:1234")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--ethertype", default="0x88b5",
                    help="EtherType, e.g. 0x88b5 (ignored in --mode icmp)")
    ap.add_argument("--mode", choices=("ethertype", "icmp"), default="ethertype",
                    help="ethertype: raw frame with an unhandled EtherType. "
                         "icmp: well-formed IPv4/ICMP echo request or reply.")
    ap.add_argument("--icmp-type", type=int, default=8,
                    help="8 = Echo Request, 0 = Echo Reply")
    ap.add_argument("--icmp-id", type=lambda s: int(s, 0), default=0,
                    help="ICMP identifier (must match the guest's "
                         "ping_identifier for an Echo Reply to be accepted)")
    ap.add_argument("--src-ip", default="10.0.2.99")
    ap.add_argument("--dst-ip", default="10.0.2.15")
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

    if args.mode == "icmp":
        frame = build_icmp_frame(args.dst, args.src, args.src_ip, args.dst_ip,
                                 args.icmp_type, args.icmp_id, 1,
                                 args.payload_len)
        desc = f"icmp type {args.icmp_type} id 0x{args.icmp_id:04x}"
    else:
        frame = build_frame(args.dst, args.src, ethertype, args.payload_len)
        desc = f"ethertype 0x{ethertype:04x}"

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

    print(f"sent {args.count} frames, {desc}, {len(frame)} bytes each")


if __name__ == "__main__":
    main()
