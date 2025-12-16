#!/usr/bin/env python3
import pandas as pd
import numpy as np
import time
import sys
import os
import csv
import warnings

# Tắt cảnh báo Pandas (FutureWarning) để log sạch sẽ
warnings.simplefilter(action='ignore', category=FutureWarning)

# --- CẤU HÌNH ---
INPUT_FILE = "raw.csv" 
PROCESSING_FILE = "raw_processing.csv"     # File tạm để xử lý
OUTPUT_FEATURE_FILE = "calculated_features.csv" # File kết quả cho Module 3

ARP_PROTO_ID = 2054 

# --- DANH SÁCH FEATURE ---
MODEL_FEATURE_COLUMNS = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number', 'rst_flag_number',
    'ack_count', 'syn_count', 'urg_count', 'rst_count', 'fin_count',
    'Min', 'Max', 'AVG', 'IAT',
    'Number', 'Magnitue', 'Radius', 'Variance', 'Weight',
    'APS', 'ABPS', 'subARP' 
]

def get_flow_key(row):
    """Tạo khóa luồng."""
    if row['Protocol'] == ARP_PROTO_ID: return "ARP_Flow"
    if row['Source_IP'] < row['Destination_IP']:
        return str((row['Source_IP'], row['Source_Port'], row['Destination_IP'], row['Destination_Port'], row['Protocol']))
    return str((row['Destination_IP'], row['Destination_Port'], row['Source_IP'], row['Source_Port'], row['Protocol']))

def calculate_features_from_group(group):
    """Tính toán 26 feature cho một luồng."""
    try:
        first_pkt = group.iloc[0]
        proto = first_pkt['Protocol']
        group = group.sort_values(by='Timestamp')
        
        features = {col: 0 for col in MODEL_FEATURE_COLUMNS}
        features['Protocol Type'] = proto

        f_flow_duration = group['Timestamp'].max() - group['Timestamp'].min()
        if f_flow_duration <= 0: f_flow_duration = 0.000001
        
        f_number = len(group)
        f_rate = f_number / f_flow_duration
        
        features['flow_duration'] = f_flow_duration
        features['Rate'] = f_rate
        features['Number'] = f_number

        # --- TÍNH TOÁN ARP ---
        if proto == ARP_PROTO_ID:
            features['APS'] = len(group) / f_flow_duration
            broadcast_count = group[group['Eth_Dst'] == 'ff:ff:ff:ff:ff:ff'].shape[0]
            features['ABPS'] = broadcast_count / f_flow_duration
            arp_requests = group[group['ARP_Opcode'] == 1].shape[0]
            arp_replies = group[group['ARP_Opcode'] == 2].shape[0]
            features['subARP'] = arp_replies - arp_requests
            
        # --- TÍNH TOÁN TCP/IP ---
        else:
            fwd_ip = first_pkt['Source_IP']
            fwd_pkts = group[group['Source_IP'] == fwd_ip]
            bwd_pkts = group[group['Source_IP'] != fwd_ip]
            
            all_lengths = group['Packet_Length']
            f_min_len = all_lengths.min()
            f_max_len = all_lengths.max()
            f_avg_len = all_lengths.mean()
            
            f_iat_mean = 0
            if len(group) > 1:
                iat_list = group['Timestamp'].diff().dropna()
                f_iat_mean = iat_list.mean()
            else:
                f_iat_mean = f_flow_duration

            avg_fwd_len = fwd_pkts['Packet_Length'].mean() if not fwd_pkts.empty else 0
            avg_bwd_len = bwd_pkts['Packet_Length'].mean() if not bwd_pkts.empty else 0
            var_fwd_len = fwd_pkts['Packet_Length'].var(ddof=0) if len(fwd_pkts) > 1 else 0
            var_bwd_len = bwd_pkts['Packet_Length'].var(ddof=0) if len(bwd_pkts) > 1 else 0
            var_fwd_len = np.nan_to_num(var_fwd_len)
            var_bwd_len = np.nan_to_num(var_bwd_len)

            f_magnitue = (avg_fwd_len + avg_bwd_len) * 0.5
            f_radius = (var_fwd_len + var_bwd_len) * 0.5
            f_variance = (var_fwd_len / var_bwd_len) if var_bwd_len > 0 else 0
            f_weight = len(fwd_pkts) * len(bwd_pkts)
            
            f_header_len = first_pkt['IP_Header_Len']
            if proto == 6: # TCP
                f_header_len = group['IP_Header_Len'].mean() + group['TCP_Header_Len'].mean()
                first_flags = str(first_pkt['Flags'])
                features['fin_flag_number'] = 1 if 'F' in first_flags else 0
                features['syn_flag_number'] = 1 if 'S' in first_flags else 0
                features['psh_flag_number'] = 1 if 'P' in first_flags else 0
                features['ack_flag_number'] = 1 if 'A' in first_flags else 0
                features['rst_flag_number'] = 1 if 'R' in first_flags else 0
                features['ack_count'] = group['Flags'].astype(str).str.contains('A').sum()
                features['syn_count'] = group['Flags'].astype(str).str.contains('S').sum()
                features['urg_count'] = group['Flags'].astype(str).str.contains('U').sum()
                features['rst_count'] = group['Flags'].astype(str).str.contains('R').sum()
                features['fin_count'] = group['Flags'].astype(str).str.contains('F').sum()

            features.update({
                'Header_Length': f_header_len, 'Min': f_min_len, 'Max': f_max_len, 
                'AVG': f_avg_len, 'IAT': f_iat_mean, 'Magnitue': f_magnitue, 
                'Radius': f_radius, 'Variance': f_variance, 'Weight': f_weight,
            })

        return pd.Series(features, index=MODEL_FEATURE_COLUMNS)
        
    except Exception:
        return None

def process_raw_file(filepath):
    """Đọc raw, tính feature và BÀN GIAO cho Module 3."""
    try:
        # Thêm encoding='utf-8' để tránh lỗi ký tự lạ trên Windows
        df_raw = pd.read_csv(filepath, encoding='utf-8')
        if df_raw.empty: return

        print(f"[Module 2] Đang tính toán feature cho {len(df_raw)} gói tin...")

        df_raw['Flow_Key'] = df_raw.apply(get_flow_key, axis=1)
        
        # Tính toán feature
        features_df = df_raw.groupby('Flow_Key').apply(calculate_features_from_group)
        
        # Ghi đè (mode='w') vào file output
        features_df.to_csv(OUTPUT_FEATURE_FILE, mode='w', header=True, index=False, encoding='utf-8')
        
        print(f"[Module 2] Đã tạo {len(features_df)} luồng feature.")

    except Exception as e:
        print(f"[Module 2] Lỗi tính toán: {e}")

if __name__ == "__main__":
    if os.path.exists(INPUT_FILE):
        try:
            # --- LOGIC AN TOÀN CHO WINDOWS ---
            # 1. Xóa file đích cũ nếu tồn tại (Windows không cho overwrite khi rename)
            if os.path.exists(PROCESSING_FILE):
                try:
                    os.remove(PROCESSING_FILE)
                except PermissionError:
                    print("[Module 2] File đang bận, bỏ qua chu kỳ này.")
                    sys.exit(0)

            # 2. Đổi tên file để "khóa" (Atomic operation)
            try:
                os.rename(INPUT_FILE, PROCESSING_FILE)
            except PermissionError:
                print("[Module 2] Không thể truy cập file raw.csv (đang được ghi).")
                sys.exit(0)
            
            # 3. Xử lý
            process_raw_file(PROCESSING_FILE)
            
            # 4. Dọn dẹp
            if os.path.exists(PROCESSING_FILE):
                try: os.remove(PROCESSING_FILE)
                except: pass
                
        except Exception as e:
            print(f"[Module 2] Lỗi hệ thống: {e}")
            if os.path.exists(PROCESSING_FILE):
                try: os.remove(PROCESSING_FILE)
                except: pass