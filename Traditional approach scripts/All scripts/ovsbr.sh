ip tuntap add mode tap vp1
ifconfig vp1 up
ovs-vsctl add-port br0 vp1
ip tuntap add mode tap vp2
ifconfig vp2 up
ovs-vsctl add-port br0 vp2
ip tuntap add mode tap vp3
ifconfig vp3 up
ovs-vsctl add-port br0 vp3
ip tuntap add mode tap vp4
ifconfig vp4 up
ovs-vsctl add-port br0 vp4
