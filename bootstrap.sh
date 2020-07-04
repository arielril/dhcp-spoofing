sudo apt update -y 
sudo apt upgrade -y 
sudo apt autoremove 
sudo apt remove

# start core daemon
/etc/init.d/core-daemon start
sudo service core-daemon start
sudo service core-daemon restart

echo "" >> ~/.bashrc
echo "cd /vagrant" >> ~/.bashrc
