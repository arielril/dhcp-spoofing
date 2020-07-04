# Update apt cache
apt update

# Generic packages
apt -y install wget python3.6 python3-pip

# Install quagga
apt -y install quagga

# URL to download core
COREPKG=https://github.com/coreemu/core/releases/download/release-6.5.0/core_6.5.0_amd64.deb
COREDAEMONDEP=https://raw.githubusercontent.com/coreemu/core/master/daemon/requirements.txt

# get core package
wget -c $COREPKG

# get core package requirements
wget -c $COREDAEMONDEP

apt -y install git automake pkg-config gcc libev-dev ebtables iproute2 \
    python3.6 python3.6-dev python3-pip python3-tk tk libtk-img ethtool autoconf \
    mgen traceroute snmpd snmp-mibs-downloader snmptrapd \
    mgen-doc make libreadline-dev imagemagick help2man apache2 tcl libev4

python3 -m pip install grpcio-tools
python3 -m pip install -r requirements.txt

sudo dpkg -i core_6.5.0_amd64.deb

# Install wireshark enabled for non-root users
DEBIAN_FRONTEND=noninteractive apt -y install wireshark
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
usermod -a -G wireshark vagrant

# start core daemon
/etc/init.d/core-daemon start
systemctl daemon-reload
systemctl start core-daemon

reboot -h now
