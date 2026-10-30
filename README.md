# User-Space IPv4 Router & ICMP Engine
Chương trình giả lập Router tầng Mạng (Layer 3) chạy ở không gian người dùng (User-Space) viết bằng Python. Dự án hỗ trợ xử lý luồng gói tin IPv4, tra cứu bảng định tuyến bằng thuật toán Longest-Prefix Match (cấu trúc cây Trie) và phản hồi các thông điệp giao thức ICMP.
---
## 👥 Phân công Nhiệm vụ Thành viên
| Thành viên | Vai trò | Trách nhiệm chính |
| :--- | :--- | :--- |
| **TV1** | IP Core Engine | Khởi tạo Raw Socket, bóc tách/đóng gói IPv4 Header (`struct`), tính toán Checksum và giảm TTL. |
| **TV2** | Routing Engine | Xây dựng cấu trúc cây Trie, nạp bảng định tuyến và triển khai thuật toán tra cứu Longest-Prefix Match. |
| **TV3** | ICMP & Testing | Triển khai ICMP Engine (Echo Reply, Time Exceeded, Destination Unreachable), viết Unit Tests và dựng môi trường kiểm thử. |
---
## 📁 Cấu trúc Thư mục Dự án
```text
userspace-ipv4-router/
├── core/              # TV1: Module xử lý IPv4 Header & Checksum
├── routing/           # TV2: Module cây Trie & Bảng định tuyến
├── icmp/              # TV3: Module đóng gói & xử lý lỗi ICMP
├── tests/             # TV3: Bộ Unit Test và kịch bản thử nghiệm
├── config/            # Chứa file cấu hình bảng định tuyến (routes.txt)
├── main.py            # Chương trình chính khởi chạy Router
└── README.md          # Tài liệu hướng dẫn dự án# userspace-ipv4-router
User-Space IPv4 Router &amp; ICMP Engine for Data Communications course
