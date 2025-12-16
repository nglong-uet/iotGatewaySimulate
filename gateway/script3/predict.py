#!/usr/bin/env python3
import pandas as pd
import numpy as np
import joblib
import time
import sys
import os
import csv
import warnings

# Suppress warnings
warnings.filterwarnings("ignore")

# --- CONFIGURATION ---
CHECK_INTERVAL_SEC = 1.0 
INPUT_FILE = "calculated_features.csv"
PROCESSING_FILE = "features_processing.csv"
OUTPUT_FINAL_FILE = "final.csv"
MODEL_FILE = "xgboost_model.joblib" 
API_ENDPOINT = "http://your-api-server/alert"

# --- THRESHOLDS FOR RULE-BASED DETECTION ---
THRESHOLD_SUBARP = 0    # subARP > 0 -> Definitely MITM
THRESHOLD_RATE = 1000   # Rate > 1000 -> Suspected DoS

# --- LABEL MAPPING ---
LABEL_MAPPING = [
    'DDoS-ACK_Fragmentation',    # 0
    'DDoS-ICMP_Flood',           # 1
    'DDoS-ICMP_Fragmentation',   # 2
    'DDoS-PSHACK_Flood',         # 3
    'DDoS-RSTFINFlood',          # 4
    'DDoS-SYN_Flood',            # 5
    'DDoS-SynonymousIP_Flood',   # 6
    'DDoS-TCP_Flood',            # 7
    'DDoS-UDP_Flood',            # 8
    'DDoS-UDP_Fragmentation',    # 9
    'DoS-SYN_Flood',             # 10
    'DoS-TCP_Flood',             # 11
    'DoS-UDP_Flood',             # 12
    'MITM-ArpSpoofing',          # 13
    'Benign'                     # 14 
]

# --- FEATURE LIST ---
MODEL_FEATURE_COLUMNS = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Rate',
    'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number', 'rst_flag_number',
    'ack_count', 'syn_count', 'urg_count', 'rst_count', 'fin_count',
    'Min', 'Max', 'AVG', 'IAT',
    'Number', 'Magnitue', 'Radius', 'Variance', 'Weight'
]

ALL_INPUT_COLUMNS = MODEL_FEATURE_COLUMNS + ['APS', 'ABPS', 'subARP']
FINAL_LOG_COLUMNS = ALL_INPUT_COLUMNS + ['Predicted_Label', 'Detection_Method']

def initialize_csv_header(filepath, columns):
    if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0:
        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(columns)
        except Exception as e:
            print(f"[Module 3] Error initializing header: {e}")

def call_api_for_alert(label_text, flow_count):
    print("---------------------------------")
    print(f"!!!!!!!!!! ATTACK ALERT !!!!!!!!!!!")
    print(f"TYPE: {label_text} (Count: {flow_count})")
    print(f"Calling API: {API_ENDPOINT}...")
    print("---------------------------------")

def map_label(num):
    try:
        return LABEL_MAPPING[int(num)]
    except IndexError:
        return f"Unknown_Label_{num}"

def run_predictor(model):
    try:
        # 1. Read Feature File
        # Use simple try-except for reading to avoid locking issues
        try:
            df_features = pd.read_csv(PROCESSING_FILE)
        except pd.errors.EmptyDataError:
            return

        if df_features.empty: return

        print(f"[Module 3] Read {len(df_features)} flows. Analyzing...")

        # 2. Prepare Data Structure
        df_full = pd.DataFrame(columns=ALL_INPUT_COLUMNS)
        df_full = pd.concat([df_full, df_features], ignore_index=True).fillna(0)

        df_full['Predicted_Label'] = None
        df_full['Detection_Method'] = None

        # ---------------------------------------------------------
        # STEP 3: APPLY RULE-BASED FIRST (Vectorization)
        # ---------------------------------------------------------
        
        # Rule 1: ARP Spoofing
        mask_arp = df_full['subARP'] > THRESHOLD_SUBARP
        if mask_arp.any():
            df_full.loc[mask_arp, 'Predicted_Label'] = "MITM-ArpSpoofing"
            df_full.loc[mask_arp, 'Detection_Method'] = "Rule-Based (subARP)"
            print(f"[*] Rule ARP caught {mask_arp.sum()} flows.")

        # Rule 2: DoS High Rate
        mask_dos = (df_full['Rate'] > THRESHOLD_RATE) & (df_full['Predicted_Label'].isnull())
        if mask_dos.any():
            df_full.loc[mask_dos, 'Predicted_Label'] = "DoS-High_Rate_Attack"
            df_full.loc[mask_dos, 'Detection_Method'] = "Rule-Based (Rate)"
            print(f"[*] Rule DoS caught {mask_dos.sum()} flows.")

        # ---------------------------------------------------------
        # STEP 4: RUN ML FOR REMAINING ROWS
        # ---------------------------------------------------------
        
        mask_ml = df_full['Predicted_Label'].isnull()
        
        if mask_ml.any():
            X_subset = df_full.loc[mask_ml, MODEL_FEATURE_COLUMNS].values
            
            predictions_num = model.predict(X_subset)
            predictions_text = [map_label(n) for n in predictions_num]
            
            df_full.loc[mask_ml, 'Predicted_Label'] = predictions_text
            df_full.loc[mask_ml, 'Detection_Method'] = "ML-Model"

        # ---------------------------------------------------------
        # STEP 5: OUTPUT & ALERT
        # ---------------------------------------------------------

        initialize_csv_header(OUTPUT_FINAL_FILE, FINAL_LOG_COLUMNS)
        df_full.to_csv(OUTPUT_FINAL_FILE, mode='a', header=False, index=False)
        
        print(f"[*] [Module 3] Analyzed {len(df_full)} flows.")

        attack_counts = df_full.groupby(['Predicted_Label', 'Detection_Method']).size()
        
        is_under_attack = False
        for (label, method), count in attack_counts.items():
            if label != 'Benign':
                is_under_attack = True
                print(f"[*] [Module 3] DETECTED: {count} flows of {label}")
                call_api_for_alert(label, count, method)
        
        if not is_under_attack:
            print("[*] [Module 3] STATUS: NORMAL.")

    except Exception as e:
        print(f"[!] Critical Error in Module 3: {e}", file=sys.stderr)

# --- MAIN LOOP ---
if __name__ == "__main__":
    print(f"[*] [Module 3] Starting Hybrid Detection System (Windows Optimized)...")
    
    # Load Model
    try:
        # model = joblib.load(MODEL_FILE)
        model = None
        print(f"[*] [Module 3] Model '{MODEL_FILE}' loaded.")
    except Exception as e:
        print(f"[!] Error loading model: {e}")
        sys.exit(1)

    # Infinite Loop (Uncomment for Daemon mode)
    # while True:
    
    if os.path.exists(INPUT_FILE):
        try:
            # --- WINDOWS SAFE FILE HANDLING ---
            # 1. Clean up target file first
            if os.path.exists(PROCESSING_FILE):
                try:
                    os.remove(PROCESSING_FILE)
                except PermissionError:
                    print("[Module 3] Target file locked. Skipping this cycle.")
                    sys.exit(0) # Or continue

            # 2. Rename (Move) file
            try:
                os.rename(INPUT_FILE, PROCESSING_FILE)
            except PermissionError:
                print("[Module 3] Input file locked by Module 2. Skipping.")
                sys.exit(0)

            # 3. Run Logic
            run_predictor(model)
            
            # 4. Clean up processed file
            if os.path.exists(PROCESSING_FILE):
                try: os.remove(PROCESSING_FILE)
                except: pass

        except Exception as e:
            print(f"[!] Error processing file: {e}")
            if os.path.exists(PROCESSING_FILE):
                try: os.remove(PROCESSING_FILE)
                except: pass
    
    # time.sleep(CHECK_INTERVAL_SEC)