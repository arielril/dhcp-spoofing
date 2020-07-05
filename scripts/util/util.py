import socket


def bytesToMac(macBytes: bytes) -> str:
    return ':'.join('{:02x}'.format(x) for x in macBytes)


def computeChecksum(msg: bytes) -> int:
    s = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)
