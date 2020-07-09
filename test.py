
usedSuff = [100]
usedIPs = ['10.0.0.100']
offeredIPs = ['10.0.0.100']
maxIP = 126

def getIP():
    print('used', usedSuff)
    print('max', maxIP)
    last = 100
    ip = 0

    lastSuff = usedSuff[len(usedSuff)-1]

    if lastSuff:
        ip = lastSuff + 1
    else:
        ip = last

    if ip > maxIP:
        ip = ''

    usedSuff.append(ip)
    return '10.0.0.' + str(ip)

for i in range(10):
    print('result', getIP())

