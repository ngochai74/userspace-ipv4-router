
#!/bin/bash
ip netns del host1 2>/dev/null
ip netns del host2 2>/dev/null
ip link del veth-rt1 2>/dev/null
ip link del veth-rt2 2>/dev/null

ip netns add host1
ip netns add host2

ip link add veth-h1 type veth peer name veth-rt1
ip link add veth-h2 type veth peer name veth-rt2

ip link set veth-h1 netns host1
ip link set veth-h2 netns host2

ip netns exec host1 ip link set lo up
ip netns exec host1 ip link set veth-h1 address 00:00:00:00:01:10
ip netns exec host1 ip addr add 192.168.1.10/24 dev veth-h1
ip netns exec host1 ip link set veth-h1 up
ip netns exec host1 ip route add default via 192.168.1.1

ip netns exec host2 ip link set lo up
ip netns exec host2 ip link set veth-h2 address 00:00:00:00:02:20
ip netns exec host2 ip addr add 192.168.2.20/24 dev veth-h2
ip netns exec host2 ip link set veth-h2 up
ip netns exec host2 ip route add default via 192.168.2.1

sysctl -w net.ipv4.ip_forward=0 >/dev/null
ip addr add 192.168.1.1/24 dev veth-rt1
ip addr add 192.168.2.1/24 dev veth-rt2
ip link set veth-rt1 up
ip link set veth-rt2 up

echo " Đã dựng xong topology: Host1 (192.168.1.10) <---> Router <---> Host2 (192.168.2.20)"
