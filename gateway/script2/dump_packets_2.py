#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import json
import csv
import ctypes # Thư viện kiểm tra quyền trên Windows

# --- CẤU HÌNH ---
# LƯU Ý: Chạy 'tshark -D' trong CMD để lấy số Interface đúng
INTERFACE = "5" 

CAPTURE_DURATION_SEC = 3
RAW_TEMP_FILE = "raw_temp.csv"
RAW_FINAL_FILE = "raw.csv"
RAW_FLOW_LOG_FILE = "raw_flow.csv"
TERMINAL_LOG_FILE = "log_terminal.log"

# Đường dẫn TShark (Nếu đã có trong PATH thì để 'tshark')
# Nếu lỗi không tìm thấy file, hãy điền đường dẫn full: r"C:\Program Files\Wireshark\tshark.exe"
TSHARK_COMMAND = [
    'tshark', '-i', INTERFACE, '-a', f'duration:{CAPTURE_DURATION_SEC}',
    '-T', 'json', '-l', 
    '-f', 'ip or arp',
    '-e', 'frame.time_epoch', '-e', 'frame.len', '-e', 'eth.type',
    '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ip.proto', '-e', 'ip.hdr_len',
    '-e', 'tcp.hdr_len', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
    '-e', 'udp.srcport', '-e', 'udp.dstport', '-e', 'tcp.flags',
    '-e', 'arp.opcode', '-e', 'eth.dst', '-e', 'arp.src.hw_mac', '-e', 'arp.src.proto_ipv4'
]

RAW_FILE_COLUMNS = [
    'Timestamp', 'Source_IP', 'Source_Port', 'Destination_IP', 'Destination_Port',
    'Protocol', 'Packet_Length', 'Flags', 'IP_Header_Len', 'TCP_Header_Len',
    'ARP_Opcode', 'Eth_Dst', 'ARP_Src_MAC', 'ARP_Src_IP'
]

def is_admin():
    """Hàm kiểm tra quyền Admin tương thích cả Windows và Linux"""
    try:
        # Thử cách của Linux trước
        return os.getuid() == 0
    except AttributeError:
        # Nếu lỗi (là Windows), dùng cách của Windows
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def log_to_file_and_print(message):
    print(message)
    try:
        with open(TERMINAL_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except: pass

def initialize_csv_header(filepath, columns):
    if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0:
        try:
            with open(filepath, 'w', newline='') as csvfile:
                csv.writer(csvfile).writerow(columns)
        except Exception as e:
             log_to_file_and_print(f"[!] Lỗi khởi tạo CSV {filepath}: {e}")

def run_capture_cycle():
    log_to_file_and_print(f"[*] [Module 1] Bắt đầu lắng nghe {CAPTURE_DURATION_SEC}s...")
    packets_written = 0
    try:
        with open(RAW_TEMP_FILE, 'w', newline='') as temp_csv_file:
            writer = csv.writer(temp_csv_file)
            writer.writerow(RAW_FILE_COLUMNS)
            
            initialize_csv_header(RAW_FLOW_LOG_FILE, RAW_FILE_COLUMNS)
            flow_file = open(RAW_FLOW_LOG_FILE, 'a', newline='')
            flow_writer = csv.writer(flow_file)

            # shell=False, encoding='utf-8', errors='ignore' để an toàn trên Windows
            process = subprocess.Popen(TSHARK_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            stdout, _ = process.communicate()

            if not stdout.strip():
                flow_file.close()
                return 0

            try: packets = json.loads(stdout)
            except: 
                flow_file.close()
                return 0

            for packet in packets:
                layers = packet.get('_source', {}).get('layers', {})
                if not layers: continue

                pkt_time = layers.get('frame.time_epoch', ['0'])[0]
                pkt_len = int(layers.get('frame.len', [0])[0])
                
                eth_type_str = layers.get('eth.type', ['0'])[0]
                try: eth_type = int(str(eth_type_str), 16)
                except: eth_type = 0
                
                src_ip, dst_ip, flags_str = '0.0.0.0', '0.0.0.0', ''
                src_port, dst_port, ip_header_len, tcp_header_len = 0, 0, 0, 0
                proto, arp_opcode = 0, 0
                eth_dst = layers.get('eth.dst', [''])[0]
                arp_src_mac = layers.get('arp.src.hw_mac', [''])[0]
                arp_src_ip = layers.get('arp.src.proto_ipv4', [''])[0]

                if eth_type == 0x0800: # IP
                    src_ip = layers.get('ip.src', ['0.0.0.0'])[0]
                    dst_ip = layers.get('ip.dst', ['0.0.0.0'])[0]
                    proto = int(layers.get('ip.proto', [0])[0])
                    ip_header_len = int(layers.get('ip.hdr_len', [0])[0])
                    if proto == 6: # TCP
                        src_port = int(layers.get('tcp.srcport', [0])[0])
                        dst_port = int(layers.get('tcp.dstport', [0])[0])
                        tcp_header_len = int(layers.get('tcp.hdr_len', [0])[0])
                        try:
                            flags_val = layers.get('tcp.flags', ["0"])[0]
                            flags_hex = int(str(flags_val), 16)
                            if (flags_hex & 0x01): flags_str += 'F'
                            if (flags_hex & 0x02): flags_str += 'S'
                            if (flags_hex & 0x04): flags_str += 'R'
                            if (flags_hex & 0x08): flags_str += 'P'
                            if (flags_hex & 0x10): flags_str += 'A'
                            if (flags_hex & 0x20): flags_str += 'U'
                        except: pass
                    elif proto == 17: # UDP
                        src_port = int(layers.get('udp.srcport', [0])[0])
                        dst_port = int(layers.get('udp.dstport', [0])[0])
                elif eth_type == 0x0806: # ARP
                    proto = 2054
                    arp_opcode = int(layers.get('arp.opcode', [0])[0])

                row_data = [pkt_time, src_ip, src_port, dst_ip, dst_port, proto, pkt_len, flags_str, ip_header_len, tcp_header_len, 
                            arp_opcode, eth_dst, arp_src_mac, arp_src_ip] 

                writer.writerow(row_data)
                flow_writer.writerow(row_data)
                packets_written += 1
            
            flow_file.close()
            
    except Exception as e:
        log_to_file_and_print(f"[!] Lỗi Module 1: {e}")
        return 0
    
    return packets_written

if __name__ == "__main__":
    # SỬA LỖI: Dùng hàm kiểm tra quyền mới
    if not is_admin():
        print("[!] CẢNH BÁO: Script nên chạy với quyền Administrator/Root để bắt gói tin.")
        # sys.exit(1) # Có thể bỏ comment nếu muốn bắt buộc

    packets = run_capture_cycle()
    if packets > 0:
        try:
            if os.path.exists(RAW_FINAL_FILE): os.remove(RAW_FINAL_FILE)
            os.rename(RAW_TEMP_FILE, RAW_FINAL_FILE)
            log_to_file_and_print(f"[*] [Module 1] Bàn giao {packets} gói tin.")
        except: pass