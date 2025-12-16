#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, conf
import sys
import os
import csv
import time
import ctypes # Thư viện để check quyền Admin trên Windows

# --- CẤU HÌNH ---
# Trên Windows, tên interface thường là "Wi-Fi" hoặc "Ethernet"
# Để xem danh sách tên đúng, mở CMD chạy: "getmac" hoặc xem trong Network Connections
# Hoặc để None để Scapy tự chọn interface mặc định
INTERFACE = "Wi-Fi" 

# Fail-safe logic: Dừng khi hết 5 giây HOẶC bắt đủ gói
CAPTURE_DURATION_SEC = 5
CAPTURE_PACKET_COUNT = 1000 

RAW_TEMP_FILE = "raw_temp.csv"
RAW_FINAL_FILE = "raw.csv"
RAW_FLOW_LOG_FILE = "raw_flow.csv"

# Header CSV (Phải KHỚP 100% với Module 2)
RAW_FILE_COLUMNS = [
    'Timestamp', 'Source_IP', 'Source_Port', 'Destination_IP', 'Destination_Port',
    'Protocol', 'Packet_Length', 'Flags', 'IP_Header_Len', 'TCP_Header_Len',
    'ARP_Opcode', 'Eth_Dst', 'ARP_Src_MAC', 'ARP_Src_IP'
]

# Biến toàn cục để đếm số gói tin trong callback
packet_counter = 0

def is_admin():
    """Hàm kiểm tra quyền Admin trên Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_tcp_flags(pkt):
    """Chuyển đổi Flags TCP từ Scapy object sang chuỗi ký tự"""
    flags_str = ""
    if pkt.haslayer(TCP):
        f = pkt[TCP].flags
        # Scapy flags object có thể cast sang str hoặc check bit
        if 'F' in f: flags_str += 'F'
        if 'S' in f: flags_str += 'S'
        if 'R' in f: flags_str += 'R'
        if 'P' in f: flags_str += 'P'
        if 'A' in f: flags_str += 'A'
        if 'U' in f: flags_str += 'U'
    return flags_str

def process_packet(pkt, writer_temp, writer_log):
    """Hàm Callback xử lý từng gói tin"""
    global packet_counter
    
    try:
        # 1. Dữ liệu cơ bản
        pkt_time = pkt.time
        pkt_len = len(pkt)
        
        # Mặc định
        src_ip, dst_ip, flags_str = '0.0.0.0', '0.0.0.0', ''
        src_port, dst_port, ip_header_len, tcp_header_len = 0, 0, 0, 0
        proto, arp_opcode = 0, 0
        eth_dst = ''
        arp_src_mac, arp_src_ip = '', ''

        # Lấy Ethernet Destination (cho ARP Broadcast check)
        if pkt.haslayer(Ether):
            eth_dst = pkt[Ether].dst

        # --- XỬ LÝ THEO LỚP (CHỈ IP VÀ ARP) ---
        
        # Trường hợp 1: Gói tin IP (IPv4)
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            ip_header_len = pkt[IP].ihl * 4

            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_header_len = pkt[TCP].dataofs * 4
                flags_str = get_tcp_flags(pkt)
            
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
        
        # Trường hợp 2: Gói tin ARP
        elif pkt.haslayer(ARP):
            proto = 2054 # ID giả định cho ARP
            arp_opcode = pkt[ARP].op
            arp_src_mac = pkt[ARP].hwsrc
            arp_src_ip = pkt[ARP].psrc

        # LỌC CUỐI CÙNG: Chỉ ghi nếu proto đã được gán giá trị (tức là rơi vào 1 trong 2 trường hợp trên)
        if proto != 0:
            row = [pkt_time, src_ip, src_port, dst_ip, dst_port, 
                   proto, pkt_len, flags_str, ip_header_len, tcp_header_len, 
                   arp_opcode, eth_dst, arp_src_mac, arp_src_ip]
            
            writer_temp.writerow(row)
            writer_log.writerow(row)
            packet_counter += 1

    except Exception as e:
        # print(f"Lỗi parse packet: {e}") 
        pass

def run_capture():
    global packet_counter
    packet_counter = 0
    
    print(f"[*] Scapy (Windows): Bắt đầu lắng nghe trên '{INTERFACE}'...")
    print(f"[*] Cấu hình: Timeout={CAPTURE_DURATION_SEC}s HOẶC Limit={CAPTURE_PACKET_COUNT} gói")
    print(f"[*] Filter: CHỈ IP HOẶC ARP (Bỏ qua IPv6, LLDP, STP...)")

    # Mở file CSV
    with open(RAW_TEMP_FILE, 'w', newline='') as f_temp, \
         open(RAW_FLOW_LOG_FILE, 'a', newline='') as f_log:
        
        writer_temp = csv.writer(f_temp)
        writer_log = csv.writer(f_log)
        
        # Ghi Header
        writer_temp.writerow(RAW_FILE_COLUMNS)
        if os.path.getsize(RAW_FLOW_LOG_FILE) == 0:
            writer_log.writerow(RAW_FILE_COLUMNS)

        def callback(pkt):
            process_packet(pkt, writer_temp, writer_log)

        # --- SNIFF VỚI BPF FILTER ---
        # filter="ip or arp": Lệnh này gửi xuống driver Npcap.
        # Driver sẽ chỉ gửi lên Python các gói IPv4 hoặc ARP.
        # Điều này giúp giảm tải CPU tối đa vì Python không phải xử lý rác.
        sniff(iface=INTERFACE, 
              prn=callback, 
              store=False, 
              timeout=CAPTURE_DURATION_SEC, 
              count=CAPTURE_PACKET_COUNT,
              filter="ip or arp") 

    return packet_counter

if __name__ == "__main__":
    # Check quyền Admin kiểu Windows
    if not is_admin():
        print("[!] Lỗi: Vui lòng click chuột phải -> 'Run as Administrator' để bắt gói tin.")
        sys.exit(1)

    start_time = time.time()
    
    try:
        count = run_capture()
        end_time = time.time()
        duration = end_time - start_time

        if count > 0:
            # Sửa lỗi Windows: Phải xóa file đích trước khi rename
            if os.path.exists(RAW_FINAL_FILE):
                try:
                    os.remove(RAW_FINAL_FILE)
                except PermissionError:
                    print(f"[!] Lỗi: File {RAW_FINAL_FILE} đang được mở bởi chương trình khác.")
                    sys.exit(1)

            os.rename(RAW_TEMP_FILE, RAW_FINAL_FILE)
            print(f"[*] Đã bắt {count} gói trong {duration:.2f}s.")
            
            if duration < 1.0 and count >= CAPTURE_PACKET_COUNT:
                print(f"[!!!] CẢNH BÁO: Lưu lượng cực cao! Đạt ngưỡng {count} gói chỉ trong {duration:.2f}s.")
        else:
            print("[*] Không bắt được gói tin nào.")
            # Dọn dẹp file temp rỗng
            if os.path.exists(RAW_TEMP_FILE):
                os.remove(RAW_TEMP_FILE)
            
    except KeyboardInterrupt:
        print("\n[*] Đã dừng thủ công.")
    except Exception as e:
        print(f"[!] Lỗi không mong muốn: {e}")