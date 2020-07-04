import socket
import struct
import sys

from .util.format import bytesToMac

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_SIZE = 65536
ETH_LEN = 14


def isIP(eth_packet: Tuple[Any]) -> bool:
    return eth[2] == ETH_P_IP


if __name__ == "__main__":
    print('running...')
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.ntohs(ETH_P_ALL))
    except OSError as e:
        print('error creating the sniff socket', e)
        sys.exit(1)

    print('AF_PACKET sock created')
    s.bind(('eth0', 0))

    (packet, addr) = s.recvfrom(ETH_P_SIZE)

    eth_header = packet[:ETH_LEN]
    eth = struct.unpack('!6s6sH', eth_header)

    print('MAC src:', bytesToMac(eth[1]))
    print('MAC dst:', bytesToMac(eth[0]))
    print('eth type:', hex(eth[2]))

    if isIP(eth):
        print('IP packet')
