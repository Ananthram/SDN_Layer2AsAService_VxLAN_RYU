sudo apt-get update
cd
mkdir openvswitch
cd openvswitch/
ping openvswitch.org -c 1
wget http://openvswitch.org/releases/openvswitch-2.4.0.tar.gz
tar -zxvf openvswitch-2.4.0.tar.gz
cd openvswitch-2.4.0/
sudo apt-get update
sudo apt-get -y install gcc make
sudo apt-get -y install build-essential fakeroot debhelper autoconf automake libssl-dev pkg-config bzip2 openssl python-all procps python-qt4 python-zopeinterface python-twisted-conch
DEB_BUILD_OPTIONS='parallel=2 nocheck' fakeroot debian/rules binary
cd ..
sudo apt-get install dkms
sudo dpkg -i openvswitch-common*.deb openvswitch-datapath-dkms*.deb openvswitch-testcontroller*.deb openvswitch-pki*.deb openvswitch-switch*.deb
