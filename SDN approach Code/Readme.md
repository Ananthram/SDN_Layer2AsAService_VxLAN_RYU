To run the controller use command " ryu-manager VcLAN_App.py " at the controller.



Note that running the app requires RYU SDN framework being installed already in the machine running the controller app, To install RYU execute the following commands

sudo apt-get -y install git python-pip python-dev
sudo apt-get -y install python-eventlet python-routes python-webob python-paramiko
cd ~/
git clone --depth=1 https://github.com/osrg/ryu.git
sudo pip install setuptools –upgrade
cd ryu;
sudo python ./setup.py install
sudo pip install six --upgrade
sudo pip install oslo.config msgpack-python
sudo pip install eventlet --upgrade
 
 
Also the steps to create the topology are detailed in the report, however some generic commands area as follows

Adding a OvS bridge and setting it up 
ovs-vsctl add-br br0 
ovs-vsctl set-fail-mode <bridge name> secure
sudo ovs-vsctl set bridge <bridge name> protocols=OpenFlow14
ovs-vsctl set-controller br0 tcp:<IP address of Controller>:6633


Creating a port and adding it to OvS

ip tuntap add mode tap <name of port>
ifconfig <name of port> up
ovs-vsctl add-port <bridge name> <name of port>



Creating a tunnel port in OvS

ovs-vsctl add-port <OvS name> <tunnel port name> -- set interface <tunnel port name> type=vxlan option:remote_ip= <IP of Tunnel End Point> option:key=flow ofport_request=<OF port requested>