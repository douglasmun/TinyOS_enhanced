#!/usr/bin/env python3
"""A scripted DHCP server on a QEMU dgram netdev (see tools/net_peer.py for
why dgram and not socket,mcast=).

It answers the guest's boot DISCOVER with a fixed sequence of hostile and
legitimate replies and logs, in order, what it sent and what the guest sent
back. The harness (verify/verify-dhcp-config-validation.sh) grades the ORDER
of those lines; this tool only decides what to send next.

The guest's xid is read from its own DISCOVER, never guessed.

Phases, one boot:

  A  bad offers.  Each OFFER below is sent alone; the guest then has 1 s to
     answer with a REQUEST. A REQUEST means the offer was ACCEPTED -- logged,
     then NAK'd from the server-ID it was asked for so the guest rediscovers
     and the next offer is graded independently (on a fixed kernel no REQUEST
     follows and no NAK is needed).
  B  NAK while REQUESTING.  A valid OFFER must draw a REQUEST (positive
     control). Then a NAK from the wrong server and a NAK with no server-ID:
     a DISCOVER within 1.5 s means one was HONORED. Then a NAK from the right
     server, which MUST draw a DISCOVER (positive control for the NAK path).
  C  ACK for another address.  Valid OFFER -> REQUEST -> an ACK whose yiaddr
     differs from the offer, then 1 s later the correct ACK. The guest's
     banner shows which one it bound.
  D  NAK while BOUND.  A NAK from the right server with the current xid; a
     DISCOVER within 3 s means the bound lease was thrown away.

Log lines (one per event, flushed):

  peer: xid=0x.. discover|request            guest frame
  peer: offer <name> accepted|refused         phase A verdicts
  peer: sent <what>                           our frames
  peer: <phase> <result>                      phase B/D verdicts
  peer: done
"""

import argparse
import socket
import struct
import sys
import time

SERVER = "10.0.2.2"
WRONG_SERVER = "10.0.2.99"
YIADDR = "10.0.2.15"
OTHER_YIADDR = "10.0.2.99"
VALID = dict(yiaddr=YIADDR, server=SERVER, mask="255.255.255.0",
             router="10.0.2.2", dns="10.0.2.3")

# Each is the valid offer with one field made hostile (None = option absent).
BAD_OFFERS = [
    ("mask-zero",        dict(mask="0.0.0.0")),
    ("mask-holes",       dict(mask="255.0.255.0")),
    ("no-server-id",     dict(server=None)),
    ("yiaddr-bcast",     dict(yiaddr="255.255.255.255")),
    ("yiaddr-loopback",  dict(yiaddr="127.0.0.1")),
    ("yiaddr-subnet-bc", dict(yiaddr="10.0.2.255")),
    ("router-offlink",   dict(router="192.0.2.1")),
    ("dns-multicast",    dict(dns="224.0.0.251")),
]


def mac_bytes(text):
    return bytes(int(p, 16) for p in text.split(":"))


def checksum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def reply_frame(guest_mac, xid, msg_type, yiaddr=YIADDR, server=SERVER,
                mask=None, router=None, dns=None, src_ip=SERVER):
    """UDP 67->68 BOOTREPLY to the guest's MAC, IP broadcast."""
    bootp = bytearray(240)
    bootp[0], bootp[1], bootp[2] = 2, 1, 6
    struct.pack_into("!I", bootp, 4, xid)
    bootp[16:20] = socket.inet_aton(yiaddr)
    bootp[28:34] = guest_mac
    struct.pack_into("!I", bootp, 236, 0x63825363)
    opts = bytes([53, 1, msg_type])
    if server is not None:
        opts += bytes([54, 4]) + socket.inet_aton(server)
    if msg_type != 6:                                   # not a NAK
        opts += bytes([51, 4]) + struct.pack("!I", 86400)
        if mask is not None:
            opts += bytes([1, 4]) + socket.inet_aton(mask)
        if router is not None:
            opts += bytes([3, 4]) + socket.inet_aton(router)
        if dns is not None:
            opts += bytes([6, 4]) + socket.inet_aton(dns)
    body = bytes(bootp) + opts + bytes([255])

    udp = struct.pack("!HHHH", 67, 68, 8 + len(body), 0) + body
    dst = "255.255.255.255"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x4d4d, 0,
                     64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 17, len(udp)))
    csum = checksum16(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]
    server_mac = bytes.fromhex("525400020202")
    return guest_mac + server_mac + struct.pack("!H", 0x0800) + ip + udp


def parse_guest_dhcp(frame):
    """(xid, msg_type) for a guest UDP 68->67 frame, else None."""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 17:
        return None
    l4 = 14 + ihl
    sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
    if (sport, dport) != (68, 67):
        return None
    bootp = l4 + 8
    xid = struct.unpack("!I", frame[bootp + 4:bootp + 8])[0]
    i = bootp + 240
    while i < len(frame) and frame[i] != 255:
        if frame[i] == 0:
            i += 1
            continue
        if i + 1 >= len(frame):
            break
        code, ln = frame[i], frame[i + 1]
        if code == 53 and ln >= 1:
            return xid, frame[i + 2]
        i += 2 + ln
    return xid, 0


class Peer:
    def __init__(self, args):
        self.guest = mac_bytes(args.guest)
        lhost, lport = args.listen.rsplit(":", 1)
        shost, sport = args.send.rsplit(":", 1)
        self.dest = (shost, int(sport))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((lhost, int(lport)))
        self.sock.settimeout(0.1)
        self.log = open(args.out, "w")
        self.deadline = time.monotonic() + args.duration
        self.xid = None

    def say(self, text):
        print("peer: " + text, file=self.log, flush=True)

    def send(self, what, msg_type, **fields):
        self.sock.sendto(reply_frame(self.guest, self.xid, msg_type, **fields),
                         self.dest)
        self.say("sent " + what)

    def wait(self, want, seconds):
        """Wait for a guest DHCP message of type `want` (1 DISCOVER, 3
        REQUEST). Returns True if one arrived; adopts its xid."""
        end = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < end:
            try:
                frame, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            if frame[6:12] != self.guest:
                continue
            got = parse_guest_dhcp(frame)
            if got is None:
                continue
            xid, mtype = got
            name = {1: "discover", 3: "request"}.get(mtype, f"type{mtype}")
            self.say(f"xid=0x{xid:08x} {name}")
            if mtype == want:
                self.xid = xid
                return True
        return False

    def offer(self, what, **over):
        f = dict(VALID)
        f.update(over)
        self.send("offer " + what, 2, **f)

    def run(self):
        if not self.wait(1, 120):
            self.say("no discover")
            return
        # A: bad offers
        for name, over in BAD_OFFERS:
            self.offer(name, **over)
            if self.wait(3, 1.0):
                self.say(f"offer {name} accepted")
                self.send("nak (reset)", 6, server=over.get("server", SERVER) or SERVER)
                if not self.wait(1, 5.0):
                    self.say("no rediscover after reset nak")
                    return
            else:
                self.say(f"offer {name} refused")
        # B: NAKs while REQUESTING
        self.offer("valid")
        if not self.wait(3, 3.0):
            self.say("valid offer refused")
            return
        self.say("valid offer accepted")
        self.send("nak wrong-server", 6, server=WRONG_SERVER, src_ip=WRONG_SERVER)
        self.send("nak no-server-id", 6, server=None, src_ip=WRONG_SERVER)
        if self.wait(1, 1.5):
            self.say("bogus nak honored")
            self.offer("valid")
            if not self.wait(3, 3.0):
                return
        else:
            self.say("bogus nak ignored")
        self.send("nak genuine", 6)
        if self.wait(1, 3.0):
            self.say("genuine nak honored")
        else:
            self.say("genuine nak ignored")
            # Still REQUESTING under the old xid; phase C can continue.
        # C: ACK for another address, then the right one
        self.offer("valid")
        if not self.wait(3, 3.0):
            self.say("valid offer refused")
            return
        self.send("ack other-yiaddr", 5, yiaddr=OTHER_YIADDR, mask="255.255.255.0",
                  router="10.0.2.2", dns="10.0.2.3")
        time.sleep(1.0)
        self.send("ack valid", 5, mask="255.255.255.0", router="10.0.2.2",
                  dns="10.0.2.3")
        # D: NAK while BOUND
        time.sleep(2.0)
        self.send("nak while-bound", 6)
        if self.wait(1, 3.0):
            self.say("bound nak honored")
        else:
            self.say("bound nak ignored")
        self.say("done")
        # Keep draining so a late DISCOVER is still logged.
        self.wait(99, self.deadline - time.monotonic())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", required=True, help="host:port the guest sends to")
    ap.add_argument("--send", required=True, help="host:port the guest receives on")
    ap.add_argument("--guest", required=True, help="guest MAC")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--out", required=True, help="log file")
    args = ap.parse_args()
    peer = Peer(args)
    peer.say("listening")
    try:
        peer.run()
    finally:
        peer.log.close()
        peer.sock.close()


if __name__ == "__main__":
    sys.exit(main())
