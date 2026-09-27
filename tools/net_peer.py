#!/usr/bin/env python3
"""A peer on a QEMU dgram netdev: log the guest's frames and, optionally,
answer its ARP requests.

Why dgram and not the `socket,mcast=` netdev the injection harnesses use: on
macOS QEMU's mcast netdev RECEIVES injected frames but never puts the guest's
own frames on the wire (tcpdump on all interfaces sees 0 while the guest
transmits), so nothing can observe what the guest sends. A unicast dgram netdev
does deliver them:

    -netdev dgram,id=net0,local.type=inet,local.host=127.0.0.1,local.port=G,
            remote.type=inet,remote.host=127.0.0.1,remote.port=P

The guest's frames arrive at 127.0.0.1:P (--listen); frames sent to
127.0.0.1:G (--send, and inject_frames.py --mcast) reach the guest.

inject_frames.py can put frames on the guest's wire but cannot see what the
guest sends back. Harnesses that must witness the SYMPTOM -- which MAC a ping
was addressed to, which echo requests were answered -- run this alongside.

Every frame whose Ethernet source is --guest is written to --out, one line:

    dst=<mac> src=<mac> type=<ethertype> [arp op=N spa=IP tpa=IP]
                                         [ip src=IP dst=IP [icmp type=N id=0xNNNN]]

Only guest-sourced frames are logged: the group loops back every injected
frame, including this tool's own ARP replies.

--arp-reply IP=MAC answers the guest's "who-has IP" with "IP is-at MAC",
modelling the legitimate owner of IP. Needs no root: an ordinary UDP socket.
"""

import argparse
import socket
import struct
import sys
import time


def mac_bytes(text):
    parts = text.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC must be six colon-separated octets")
    return bytes(int(p, 16) for p in parts)


def fmt_mac(b):
    return ":".join(f"{x:02x}" for x in b)


def describe(frame):
    dst, src = frame[0:6], frame[6:12]
    etype = struct.unpack("!H", frame[12:14])[0]
    out = f"dst={fmt_mac(dst)} src={fmt_mac(src)} type=0x{etype:04x}"
    if etype == 0x0806 and len(frame) >= 42:
        op = struct.unpack("!H", frame[20:22])[0]
        spa = socket.inet_ntoa(frame[28:32])
        tpa = socket.inet_ntoa(frame[38:42])
        out += f" arp op={op} spa={spa} tpa={tpa}"
    elif etype == 0x0800 and len(frame) >= 34:
        ihl = (frame[14] & 0x0F) * 4
        proto = frame[23]
        sip = socket.inet_ntoa(frame[26:30])
        dip = socket.inet_ntoa(frame[30:34])
        out += f" ip src={sip} dst={dip} proto={proto}"
        l4 = 14 + ihl
        if proto == 1 and len(frame) >= l4 + 8:
            itype = frame[l4]
            ident = struct.unpack("!H", frame[l4 + 4:l4 + 6])[0]
            out += f" icmp type={itype} id=0x{ident:04x}"
        elif proto == 17 and len(frame) >= l4 + 8:
            sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
            out += f" udp sport={sport} dport={dport}"
            bootp = l4 + 8
            if dport == 67 and len(frame) >= bootp + 8:
                xid = struct.unpack("!I", frame[bootp + 4:bootp + 8])[0]
                out += f" dhcp xid=0x{xid:08x}"
    return out


def arp_reply(guest_mac, frame, owner_mac):
    """'spa-of-request is asked about; tpa is-at owner_mac', to the guest."""
    req_sha, req_spa, req_tpa = frame[22:28], frame[28:32], frame[38:42]
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
                      owner_mac, req_tpa, req_sha, req_spa)
    reply = guest_mac + owner_mac + struct.pack("!H", 0x0806) + arp
    return reply + bytes(max(0, 60 - len(reply)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", required=True, help="host:port the guest sends to")
    ap.add_argument("--send", required=True, help="host:port the guest receives on")
    ap.add_argument("--guest", type=mac_bytes, required=True, help="guest MAC")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--out", required=True, help="log file")
    ap.add_argument("--arp-reply", action="append", default=[],
                    metavar="IP=MAC", help="answer who-has IP with MAC")
    args = ap.parse_args()

    lhost, lport = args.listen.rsplit(":", 1)
    shost, sport = args.send.rsplit(":", 1)
    dest = (shost, int(sport))
    answers = {}
    for item in args.arp_reply:
        ip, mac = item.split("=", 1)
        answers[socket.inet_aton(ip)] = mac_bytes(mac)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((lhost, int(lport)))
    sock.settimeout(0.2)

    deadline = time.monotonic() + args.duration
    with open(args.out, "w") as log:
        print("peer: listening", file=log, flush=True)
        while time.monotonic() < deadline:
            try:
                frame, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            # Only the guest sends to this port, but keep the filter: it is
            # what the log format promises.
            if len(frame) < 14 or frame[6:12] != args.guest:
                continue
            print(describe(frame), file=log, flush=True)
            if (answers and len(frame) >= 42
                    and struct.unpack("!H", frame[12:14])[0] == 0x0806
                    and struct.unpack("!H", frame[20:22])[0] == 1
                    and frame[38:42] in answers):
                owner = answers[frame[38:42]]
                sock.sendto(arp_reply(args.guest, frame, owner), dest)
                print(f"peer: answered who-has {socket.inet_ntoa(frame[38:42])}"
                      f" with {fmt_mac(owner)}", file=log, flush=True)
    sock.close()


if __name__ == "__main__":
    sys.exit(main())
