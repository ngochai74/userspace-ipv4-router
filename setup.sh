#!/bin/bash

# Dừng script nếu có lỗi xảy ra
set -e

echo "Bắt đầu thiết lập môi trường mạng"

# 1. Dọn dẹp môi trường cũ (nếu có)
echo "Đang xóa các cấu hình cũ"
ip netns del host1 2>/dev/null || true
ip netns del host2 2>/dev/null || true
ip link del veth-rt1 2>/dev/null || true
ip link del veth-rt2 2>/dev/null || true

# 2. Tạo Network Namespaces cho 2 host
echo "Đang tạo host1 và host2"
ip netns add host1
ip netns add host2

# 3. Tạo các cặp Veth (Virtual Ethernet)
# veth-h1 nối với veth-rt1 (cổng 1 của router)
# veth-h2 nối với veth-rt2 (cổng 2 của router)
echo "Đang tạo các liên kết Veth"
ip link add veth-h1 type veth peer name veth-rt1
ip link add veth-h2 type veth peer name veth-rt2

# 4. Gắn các veth vào đúng namespace
echo "Đang gắn cổng mạng vào namespace"
ip link set veth-h1 netns host1
ip link set veth-h2 netns host2

# (veth-rt1 và veth-rt2 sẽ nằm ở không gian mặc định - nơi router chạy)

# 5. Cấu hình IP và bật các cổng (UP)
echo "Đang cấu hình IP cho host1 (192.168.1.10/24)"
ip netns exec host1 ip addr add 192.168.1.10/24 dev veth-h1
ip netns exec host1 ip link set veth-h1 up
ip netns exec host1 ip link set lo up

echo "Đang cấu hình IP cho host2 (192.168.2.20/24)"
ip netns exec host2 ip addr add 192.168.2.20/24 dev veth-h2
ip netns exec host2 ip link set veth-h2 up
ip netns exec host2 ip link set lo up

echo "Đang bật các cổng router..."
ip link set veth-rt1 up
ip link set veth-rt2 up
ip addr add 192.168.1.1/24 dev veth-rt1
ip addr add 192.168.2.1/24 dev veth-rt2
sysctl -w net.ipv4.ip_forward=0

# 6. Thiết lập Default Gateway cho các host
echo "Đang thiết lập định tuyến tĩnh cho các host"
ip netns exec host1 ip route add default via 192.168.1.1
ip netns exec host2 ip route add default via 192.168.2.1

echo "Thiết lập thành công"
