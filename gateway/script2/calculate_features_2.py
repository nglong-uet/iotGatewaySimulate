#!/usr/bin/env python3
import pandas as pd
import numpy as np
import time
import sys
import os
import csv

# --- CẤU HÌNH ---
INPUT_FILE = "raw.csv" 
PROCESSING_FILE = "raw_processing_dataset.csv"
OUTPUT_DATASET_FILE = "dataset_collected_new.csv"
ARP_PROTO_ID = 2054 

# --- DANH SÁCH FEATURE (23 Cũ + 3 Mới = 26 Feature) ---
MODEL_FEATURE_COLUMNS = [
    # 23 Feature Lớp 3/4 (TCP/IP)
    'flow_duration', 'Header_Length', 'Protocol Type', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number', 'rst_flag_number',
    'ack_count', 'syn_count', 'urg_count', 'rst_count', 'fin_count',
    'Min', 'Max', 'AVG', 'IAT',
    'Number', 'Magnitue', 'Radius', 'Variance', 'Weight',
    
    # 3 Feature ARP
    'APS', 'ABPS', 'subARP' 
]

def get_flow_key(row):
    """Tạo khóa luồng."""
    if row['Protocol'] == ARP_PROTO_ID: return "ARP_Flow"
    # Chuyển thành chuỗi để dùng làm key
    if row['Source_IP'] < row['Destination_IP']:
        return str((row['Source_IP'], row['Source_Port'], row['Destination_IP'], row['Destination_Port'], row['Protocol']))
    return str((row['Destination_IP'], row['Destination_Port'], row['Source_IP'], row['Source_Port'], row['Protocol']))

def calculate_features_from_group(group):
    """Tính toán 26 feature."""
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

        # --- TÍNH TOÁN 3 FEATURE ARP ---
        if proto == ARP_PROTO_ID:
            features['APS'] = len(group) / f_flow_duration
            broadcast_count = group[group['Eth_Dst'] == 'ff:ff:ff:ff:ff:ff'].shape[0]
            features['ABPS'] = broadcast_count / f_flow_duration
            arp_requests = group[group['ARP_Opcode'] == 1].shape[0]
            arp_replies = group[group['ARP_Opcode'] == 2].shape[0]
            features['subARP'] = arp_replies - arp_requests
            
        # --- TÍNH TOÁN CÁC FEATURE LỚP 3/4 ---
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
        
    except Exception as e:
        return None

def process_raw_file(filepath, label_name):
    """Đọc raw, tính feature, gán nhãn và APPEND vào dataset."""
    try:
        df_raw = pd.read_csv(filepath)
        if df_raw.empty: return

        print(f"[Dataset Builder] Đang xử lý {len(df_raw)} gói tin cho nhãn '{label_name}'...")

        df_raw['Flow_Key'] = df_raw.apply(get_flow_key, axis=1)
        features_df = df_raw.groupby('Flow_Key').apply(calculate_features_from_group)
        
        # Gán nhãn
        features_df['label'] = label_name
        
        # Ghi nối (Append) vào file dataset
        file_exists = os.path.isfile(OUTPUT_DATASET_FILE)
        features_df.to_csv(OUTPUT_DATASET_FILE, mode='a', header=not file_exists, index=False)
        
        print(f"[Dataset Builder] Đã lưu {len(features_df)} dòng vào {OUTPUT_DATASET_FILE}.")

    except Exception as e:
        print(f"[Dataset Builder] Lỗi: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Lỗi: Vui lòng cung cấp tên Label!")
        print("Ví dụ: python module2_dataset_builder.py Benign")
        sys.exit(1)
        
    target_label = sys.argv[1]
    
    if os.path.exists(INPUT_FILE):
        try:
            # Sửa lỗi Windows: Xóa file đích trước khi đổi tên
            if os.path.exists(PROCESSING_FILE):
                os.remove(PROCESSING_FILE)
                
            os.rename(INPUT_FILE, PROCESSING_FILE)
            process_raw_file(PROCESSING_FILE, target_label)
            os.remove(PROCESSING_FILE)
        except Exception as e:
            print(f"Lỗi xử lý file: {e}")
            # Cố gắng dọn dẹp nếu lỗi
            if os.path.exists(PROCESSING_FILE):
                try: os.remove(PROCESSING_FILE)
                except: pass