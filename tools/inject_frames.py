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


def build_tcp_frame(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port,
                    data_offset_words, payload_len):
    """A frame whose IP layer is valid but whose TCP data_offset is chosen.

    The point of this mode is tcp_handle_packet()'s header-length validation,
    which runs BEFORE tcp_find_connection(). That ordering is what makes the
    site interesting: the guest needs no matching connection, no listening
    port and no local account for a remote host to reach it. So the IP layer
    must be genuinely well-formed (otherwise handle_ip drops the frame earlier
    and the test measures nothing), while the TCP header is deliberately not.

    data_offset_words is written into the high nibble of the offset/reserved
    byte, unshifted by the guest's own arithmetic:
      0        -> below the legal minimum of 5   (drives validation 1)
      15       -> legal by word count, but 60 bytes of header, which exceeds a
                  20-byte segment -> drives validation 2
      5        -> legal; used as the NEGATIVE CONTROL, since a frame that is
                  well-formed but matches no connection must land on the
                  no-conn counter instead, proving the malformed counter is
                  selective rather than counting everything that arrives.
    """
    payload = bytes((i % 251) for i in range(payload_len)) if payload_len else b""

    tcp = struct.pack("!HHIIBBHHH",
                      src_port, dst_port,
                      0x11223344,                 # seq
                      0x00000000,                 # ack
                      (data_offset_words & 0x0F) << 4,
                      0x02,                       # SYN
                      8192, 0, 0) + payload

    total_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0x00, total_len,
                     0x4321, 0x0000,
                     64, 6, 0,                    # protocol 6 = TCP
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

    # TCP checksum over the pseudo-header. TinyOS does not verify it today,
    # but computing it for real keeps this frame valid if that check is ever
    # added -- otherwise this harness would start silently measuring nothing.
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 6, len(tcp)))
    csum = checksum16(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]

    frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + tcp
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


def build_udp_frame(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port,
                    payload_len, udp_len_override=None, corrupt_checksum=False):
    """A well-formed IPv4 frame carrying UDP, with the length field chosen.

    handle_udp() groups its three length tests into ONE counter
    (udp_drop_length) because they are one forged-length signature; the
    checksum test is a separate attacker position and has its own. The modes
    this builder needs to reach, therefore:

      udp_len_override=None     -> honest length. Drives udp_rx_accepted, and
                                   that is the POSITIVE CONTROL: a surface
                                   that only counts failures reads identically
                                   whether the parser works or refuses
                                   everything.
      udp_len_override=4        -> below the 8-byte UDP header minimum
                                   (validation 1).
      udp_len_override=5000     -> exceeds the IP payload (validation 2). This
                                   is the OOB-read shape the counter exists
                                   for; the guest must reject it on the length
                                   test and never reach the checksum.
      corrupt_checksum=True     -> honest length, wrong checksum. Must land on
                                   udp_drop_checksum and NOT on the length
                                   counter -- that separation is the whole
                                   point of counting by attacker position.

    The checksum is computed for real in the honest case. It has to be: a
    frame that fails checksum validation would be dropped one test later than
    intended, so an "accepted" leg built on a bogus checksum would silently
    measure the checksum path instead.
    """
    payload = bytes((i % 251) for i in range(payload_len)) if payload_len else b""

    real_len = 8 + len(payload)
    wire_len = real_len if udp_len_override is None else udp_len_override

    udp = struct.pack("!HHHH", src_port, dst_port, wire_len, 0) + payload

    total_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0x00, total_len,
                     0x5678, 0x0000,
                     64, 17, 0,                   # protocol 17 = UDP
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

    # The guest checksums over `wire_len` bytes, not over what is really
    # present -- so on an oversize override we must not try to match it. Those
    # frames are meant to die on the length test anyway.
    if udp_len_override is None:
        pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
                  + struct.pack("!BBH", 0, 17, real_len))
        csum = checksum16(pseudo + udp)
        if csum == 0:
            csum = 0xFFFF          # RFC 768: 0 means "no checksum"
        if corrupt_checksum:
            csum ^= 0xFFFF
            if csum == 0:
                csum = 0x1234
        udp = udp[:6] + struct.pack("!H", csum) + udp[8:]

    frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + udp
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


DHCP_HEADER_LEN = 240          # through the magic cookie, inclusive


def build_dhcp_frame(dst_mac, src_mac, src_ip, dst_ip, xid,
                     truncate=False, bad_cookie=False):
    """A UDP/67->68 frame carrying a DHCP BOOTREPLY.

    Reachability is NOT uniform across handle_dhcp()'s counters, and the
    difference is the point:

      dhcp_drop_short  -- tested before anything else, so ANY host on the
                          segment can drive it. `truncate=True` sends fewer
                          than 240 bytes.
      dhcp_drop_cookie -- sits BEHIND an op==BOOTREPLY test and an xid match
                          against the guest's own in-flight transaction. An
                          off-path injector cannot reach it without knowing
                          that xid, which is why --dhcp-xid exists and why a
                          harness leg for this counter must source the value
                          from the guest rather than guess it. A wrong xid
                          makes the frame vanish into the silent-ignore arm
                          and the leg then measures nothing at all.

    That asymmetry is a property of the guest, not a limitation here: it means
    the cookie counter is a same-segment-race signal, while the short counter
    is genuinely remote-driven.
    """
    dhcp = bytearray(DHCP_HEADER_LEN)
    dhcp[0] = 2                                    # op = BOOTREPLY
    dhcp[1] = 1                                    # htype = Ethernet
    dhcp[2] = 6                                    # hlen
    struct.pack_into("!I", dhcp, 4, xid)
    dhcp[16:20] = socket.inet_aton("10.0.2.15")    # yiaddr
    dhcp[28:34] = src_mac                          # chaddr
    cookie = 0x63825363 ^ (0xFFFFFFFF if bad_cookie else 0)
    struct.pack_into("!I", dhcp, 236, cookie)

    body = bytes(dhcp) + bytes([53, 1, 5, 255])    # DHCPACK, end
    if truncate:
        body = body[:DHCP_HEADER_LEN - 8]

    udp = struct.pack("!HHHH", 67, 68, 8 + len(body), 0) + body

    total_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0x00, total_len,
                     0x9abc, 0x0000,
                     64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 17, len(udp)))
    csum = checksum16(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]

    frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + udp
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mcast", required=True, help="group:port, e.g. 230.0.0.1:1234")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--ethertype", default="0x88b5",
                    help="EtherType, e.g. 0x88b5 (ignored in --mode icmp)")
    ap.add_argument("--mode",
                    choices=("ethertype", "icmp", "tcp", "udp", "dhcp"),
                    default="ethertype",
                    help="ethertype: raw frame with an unhandled EtherType. "
                         "icmp: well-formed IPv4/ICMP echo request or reply. "
                         "tcp: valid IPv4 carrying a TCP header whose "
                         "data_offset is chosen by --tcp-data-offset. "
                         "udp: valid IPv4/UDP whose length field and checksum "
                         "are chosen by --udp-length / --udp-corrupt-checksum. "
                         "dhcp: UDP 67->68 BOOTREPLY, optionally truncated or "
                         "with a bad magic cookie.")
    ap.add_argument("--udp-src-port", type=int, default=40001)
    ap.add_argument("--udp-dst-port", type=int, default=9999,
                    help="default is a port with no handler: the accepted "
                         "counter increments before dispatch, so this leg "
                         "measures the parser and not a service")
    ap.add_argument("--udp-length", type=int, default=None,
                    help="value to write into the UDP length field. Omit for "
                         "an honest length (the positive control). 4 is below "
                         "the header minimum; 5000 exceeds the IP payload.")
    ap.add_argument("--udp-corrupt-checksum", action="store_true",
                    help="honest length, wrong checksum -- must land on the "
                         "checksum counter and not the length counter")
    ap.add_argument("--dhcp-xid", type=lambda s: int(s, 0), default=0,
                    help="transaction ID. Must match the guest's in-flight "
                         "xid or the frame is silently ignored well before "
                         "the cookie test -- see build_dhcp_frame().")
    ap.add_argument("--dhcp-truncate", action="store_true",
                    help="send fewer than 240 bytes (drives dhcp_drop_short)")
    ap.add_argument("--dhcp-bad-cookie", action="store_true",
                    help="corrupt the magic cookie (needs a matching "
                         "--dhcp-xid to be reachable at all)")
    ap.add_argument("--tcp-data-offset", type=int, default=0,
                    help="TCP data offset in 32-bit words. 0 or >15 is "
                         "malformed (below the 5-word minimum); 5 is legal "
                         "and used as the negative control.")
    ap.add_argument("--tcp-src-port", type=int, default=40000)
    ap.add_argument("--tcp-dst-port", type=int, default=80)
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

    if args.mode == "udp":
        frame = build_udp_frame(args.dst, args.src, args.src_ip, args.dst_ip,
                                args.udp_src_port, args.udp_dst_port,
                                args.payload_len, args.udp_length,
                                args.udp_corrupt_checksum)
        desc = ("udp length "
                + ("honest" if args.udp_length is None else str(args.udp_length))
                + (", corrupt checksum" if args.udp_corrupt_checksum else ""))
    elif args.mode == "dhcp":
        frame = build_dhcp_frame(args.dst, args.src, args.src_ip, args.dst_ip,
                                 args.dhcp_xid, args.dhcp_truncate,
                                 args.dhcp_bad_cookie)
        desc = (f"dhcp xid 0x{args.dhcp_xid:08x}"
                + (" truncated" if args.dhcp_truncate else "")
                + (" bad-cookie" if args.dhcp_bad_cookie else ""))
    elif args.mode == "tcp":
        frame = build_tcp_frame(args.dst, args.src, args.src_ip, args.dst_ip,
                                args.tcp_src_port, args.tcp_dst_port,
                                args.tcp_data_offset, 0)
        desc = f"tcp data_offset {args.tcp_data_offset} words"
    elif args.mode == "icmp":
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
