"""Create a deterministic, dependency-free demonstration libpcap capture."""
import struct

def csum(data):
    if len(data) & 1: data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def mac(text): return bytes(int(x, 16) for x in text.split(':'))
def ip(text): return bytes(int(x) for x in text.split('.'))

CLIENT = mac('02:11:22:33:44:55'); ROUTER = mac('02:aa:bb:cc:dd:ee')
SERVER = mac('02:66:77:88:99:aa'); ROGUE = mac('02:de:ad:be:ef:01')
BCAST = b'\xff' * 6

def eth(dst, src, kind, payload): return dst + src + struct.pack('!H', kind) + payload
def arp(src, target, op, spa, tpa, dst=BCAST):
    return eth(dst, src, 0x0806, struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, src, ip(spa), b'\0'*6, ip(tpa)))

def ipv4(src, dst, proto, payload, ident):
    head = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip(src), ip(dst))
    return head[:10] + struct.pack('!H', csum(head)) + head[12:] + payload

def udp(src, dst, sport, dport, payload):
    pseudo = ip(src) + ip(dst) + struct.pack('!BBH', 0, 17, 8 + len(payload))
    h = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return h[:6] + struct.pack('!H', csum(pseudo + h + payload)) + payload

def tcp(src, dst, sport, dport, seq, ack, flags, payload=b''):
    h = struct.pack('!HHIIHHHH', sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0)
    pseudo = ip(src) + ip(dst) + struct.pack('!BBH', 0, 6, len(h) + len(payload))
    return h[:16] + struct.pack('!H', csum(pseudo + h + payload)) + h[18:] + payload

def dns(tx, answer=False):
    name = b'\x07example\x03com\0'; q = name + struct.pack('!HH', 1, 1)
    if not answer: return struct.pack('!HHHHHH', tx, 0x0100, 1, 0, 0, 0) + q
    return struct.pack('!HHHHHH', tx, 0x8180, 1, 1, 0, 0) + q + struct.pack('!HHHLH4s', 0xc00c, 1, 1, 60, 4, ip('192.168.1.53'))

def dhcp(msg, xid, yi='0.0.0.0'):
    fixed = struct.pack('!BBBBIHH4s4s4s4s16s192s', 1, msg, 6, 0, xid, 0, 0, b'\0'*4, ip(yi), b'\0'*4, b'\0'*4, CLIENT + b'\0'*10, b'\0'*192)
    options = b'\x63\x82\x53\x63' + b'\x35\x01' + bytes([msg]) + b'\x36\x04' + ip('192.168.1.1') + b'\x33\x04\0\0\x1c\x20\xff'
    return fixed + options

frames = []
def add(t, payload): frames.append((t, payload))

add(1, arp(CLIENT, '192.168.1.20', 1, '0.0.0.0', '192.168.1.1'))
add(2, arp(ROUTER, '192.168.1.20', 2, '192.168.1.1', '192.168.1.20', CLIENT))
xid = 0x12345678
for t, m, yi in [(3, 1, '0.0.0.0'), (4, 2, '192.168.1.20'), (5, 3, '0.0.0.0'), (6, 5, '192.168.1.20')]:
    srcip = '0.0.0.0' if m in (1, 3) else '192.168.1.1'
    srcmac = CLIENT if m in (1, 3) else ROUTER
    dstmac = BCAST
    sport, dport = (68, 67) if m in (1, 3) else (67, 68)
    add(t, eth(dstmac, srcmac, 0x0800, ipv4(srcip, '255.255.255.255', 17, udp(srcip, '255.255.255.255', sport, dport, dhcp(m, xid, yi)), 10 + m)))
for t, tx, ans in [(7, 0x1001, 0), (8, 0x1001, 1), (9, 0x1002, 0), (10, 0x1002, 1)]:
    if not ans: s, d, sp, dp = '192.168.1.20', '192.168.1.53', 53000 + tx - 0x1001, 53
    else: s, d, sp, dp = '192.168.1.53', '192.168.1.20', 53, 53000 + tx - 0x1001
    add(t, eth(SERVER if ans else CLIENT, CLIENT if ans else SERVER, 0x0800, ipv4(s, d, 17, udp(s, d, sp, dp, dns(tx, bool(ans))), 30 + t)))
for t, flags, ack, payload in [(11, 2, 0, b''), (12, 18, 1001, b''), (13, 16, 1001, b''), (14, 24, 1001, b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'), (15, 16, 1040, b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello')]:
    s, d, sm, dm = ('192.168.1.20', '93.184.216.34', 40000, 80) if t in (11, 13, 14) else ('93.184.216.34', '192.168.1.20', 80, 40000)
    add(t, eth(SERVER if t in (12, 15) else CLIENT, CLIENT if t in (12, 15) else SERVER, 0x0800, ipv4(s, d, 6, tcp(s, d, sm, dm, 1000 if t != 12 else 2000, ack, flags, payload), 50 + t)))
add(16, eth(BCAST, CLIENT, 0x8863, struct.pack('!BBHH', 0x11, 0x09, 0x0000, 0x0101)))
add(17, eth(CLIENT, SERVER, 0x8863, struct.pack('!BBHH', 0x11, 0x07, 0x0000, 0x0101)))
for t, sender in [(18, ROUTER), (19, ROGUE), (20, ROGUE)]:
    add(t, arp(sender, '192.168.1.20', 2, '192.168.1.1', '192.168.1.20', CLIENT))

with open('samples/sample-capture.pcap', 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for sec, packet in frames:
        f.write(struct.pack('<IIII', 1700000000 + sec, sec * 1000, len(packet), len(packet)))
        f.write(packet)
