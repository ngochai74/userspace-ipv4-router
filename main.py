import socket
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from routing.parser import load_routing_table
from core.ip_decoder import decode_ip, encode_ip, decrease_ttl

def main():
    print("Starting Router...")

    route_file = "config/routes.txt"
    if not os.path.exists(route_file):
       print("Loi: Khong tim thay file routes.txt")
       return

    trie = load_routing_table(route_file)
    print("Load routing table done!")

    try:
       sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except Exception as e:
       print("Chay bang sudo di ban oi:", e)
       sys.exit(1)

    print("Dang nghe IPv4 tren cac interface...")
    print("-" * 30)

    while True:
        try:
           data, addr = sock.recvfrom(65535)
           ip_data = data[14:]
           try:
               pkt = decode_ip(ip_data)
           except ValueError:
               continue

           nhop, out_port = trie.lookup(pkt.dest_ip)

           if nhop is None:
              print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (ko co route)")
              continue
          
           new_pkt, drop_flag = decrease_ttl(pkt)
           if drop_flag:
               print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (het TTL)")
               continue
        
           final_ip_raw = encode_ip(new_pkt)
           print(f"FWD: {pkt.source_ip} -> {pkt.dest_ip} | Port: {out_port} | NextHop: {nhop}")

       except KeyboardInterrupt:
           print("\nTat router.")
           break
       except Exception as e:
           print("Loi roi:", e)

if __name__ == "__main__":
  
