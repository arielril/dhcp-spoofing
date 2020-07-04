def bytesToMac(macBytes: bytes) -> str:
    return ':'.join('{:02x}'.format(x) for x in macBytes)
