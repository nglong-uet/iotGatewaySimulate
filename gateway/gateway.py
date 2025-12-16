#!/usr/bin/env python3
"""
IoT Gateway - Hỗ trợ đa dạng cảm biến từ nhiều ESP32 qua Proxy MQTT
Tương thích với:
  - esp32_multi1: DHT11 + Rain sensor
  - esp32_multi2: MQ2 + LDR (light)
  - esp32_multi3: DHT11 + MQ2
"""
import paho.mqtt.client as mqtt
import json
import hashlib
import time
import requests
import threading
from collections import OrderedDict
import os
import uuid

# ==================== CONFIGURATION ====================
BACKEND_URL = "https://iot.theman.vn"  # Production
# BACKEND_URL = "http://localhost:8080"  # Local test

# MQTT_BROKER = "localhost"
# MQTT_PORT = 1883
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC_IN = "iot/sensor/#"
MQTT_TOPIC_OUT = "iot/response"

GATEWAY_UID = None
POLL_INTERVAL = 10

API_REGISTER = f"{BACKEND_URL}/api/v1/test/devices/register"
API_SENSOR_DATA = f"{BACKEND_URL}/api/v1/test/sensors/data"
API_IDS_ALERT = f"{BACKEND_URL}/api/v1/test/ids-alerts"

# ==================== GLOBAL STATE ====================
packet_count = 0
lock = threading.Lock()

# ==================== CHỈ THÊM HÀM IN ĐẸP (KHÔNG ẢNH HƯỞNG GÌ KHÁC) ====================
def print_packet(label, direction, seq, data):
    arrow = "←" if direction == "RECV" else "→"
    color = "\033[94m" if direction == "RECV" else "\033[92m"
    reset = "\033[0m"
    json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    print(f"{color}[{label}] {arrow} {direction} (seq={seq}): {json_str}{reset}")

# ==================== DEVICE REGISTRATION (GIỮ NGUYÊN 100%) ====================
def register_gateway():
    global GATEWAY_UID
    print("\n" + "="*60)
    print("GATEWAY REGISTRATION")
    print("="*60)

    device_uid = os.getenv("GATEWAY_UID", "GATEWAY-001").strip()
    device_name = os.getenv("DEVICE_NAME", "IoT Multi-Sensor Gateway").strip()
    location = os.getenv("LOCATION", "Lab").strip()

    if not device_uid:
        print("Device UID required! Set env var GATEWAY_UID.")
        return False

    payload = {
        "deviceUid": device_uid,
        "name": device_name,
        "description": "IoT Gateway hỗ trợ nhiều loại cảm biến (DHT, MQ2, Rain, Light)",
        "deviceType": "IoT_Gateway",
        "location": location,
        "isGateway": True
    }

    print(f"\nĐăng ký gateway: {device_uid}...")
    try:
        response = requests.post(API_REGISTER, json=payload, timeout=10, verify=False)
        if response.status_code in [200, 201]:
            print("Đăng ký thành công!")
            GATEWAY_UID = device_uid
            return True
        else:
            print(f"Đăng ký thất bại: {response.status_code} - {response.text[:200]}")
            GATEWAY_UID = device_uid  # vẫn dùng để test
            return True
    except Exception as e:
        print(f"Lỗi kết nối: {e} → vẫn dùng UID để test")
        GATEWAY_UID = device_uid
        return True

# ==================== CHECKSUM (GIỮ NGUYÊN) ====================
def calculate_checksum(data_dict):
    clean_data = {k: v for k, v in data_dict.items() if k != "checksum"}
    json_str = json.dumps(clean_data, separators=(',', ':'), ensure_ascii=False)
    md5_hash = hashlib.md5(json_str.encode('utf-8')).hexdigest()
    return int(md5_hash[:2], 16)

def validate_checksum(data):
    received = data.get("checksum")
    if received is None:
        return False
    calculated = calculate_checksum(data)
    print(f"[CHECKSUM] Nhận: {received:3d}, Tính: {calculated:3d} → {'OK' if received == calculated else 'FAIL'}")
    return received == calculated

# ==================== MQTT HANDLERS (CHỈ THÊM 2 DÒNG IN ĐẸP) ====================
def on_connect(client, userdata, flags, rc, props=None):
    print(f"\n[MQTT] Kết nối broker thành công!")
    client.subscribe(MQTT_TOPIC_IN)
    print(f"[MQTT] Đã subscribe: {MQTT_TOPIC_IN}/#")

def on_message(client, userdata, msg):
    global packet_count
    print(f"\n[MQTT] ← {msg.topic}")

    try:
        payload = msg.payload.decode('utf-8')
        data = json.loads(payload)
        dev_id = data.get("dev_id")

        if not dev_id:
            print("Thiếu dev_id → bỏ qua")
            return

        # THÊM DÒNG NÀY: in gói tin nhận được đẹp như mẫu bạn đưa
        print_packet(dev_id, "RECV", data.get("seq_num", "???"), data)

        # Kiểm tra checksum
        if not validate_checksum(data):
            print(f"Checksum lỗi từ {dev_id} → bỏ gói tin")
            return

        with lock:
            packet_count += 1

        print(f"Đã nhận từ {dev_id} | Seq: {data.get('seq_num')} | RSSI: {data.get('rssi')} dBm")

        # Gửi lên backend (giữ nguyên hoàn toàn)
        send_to_backend(data, dev_id)

    except Exception as e:
        print(f"Lỗi xử lý tin nhắn: {e}")

# ==================== GỬI DỮ LIỆU LÊN BACKEND (CHỈ THÊM rawData + in đẹp + check response) ====================
def send_to_backend(data, dev_id):
    timestamp_ms = int(time.time() * 1000)
    sensors = []

    # === Xử lý từng loại cảm biến theo dev_id (GIỮ NGUYÊN HOÀN TOÀN CODE CỦA BẠN) ===
    if dev_id == "esp32_multi1":
        temp = data.get("temperature")
        hum = data.get("humidity")
        rain = data.get("rain_status")

        if temp is not None and temp > -999:
            sensors.append({
                "sensorUid": f"{dev_id}_dht_temp",
                "type": "TEMPERATURE",
                "data": {"temperature": round(temp, 1)}
            })
        if hum is not None and hum > -999:
            sensors.append({
                "sensorUid": f"{dev_id}_dht_hum",
                "type": "HUMIDITY",
                "data": {"humidity": round(hum, 1)}
            })
        if rain is not None:
            sensors.append({
                "sensorUid": f"{dev_id}_rain",
                "type": "RAIN",
                "data": {"rain_detected": bool(rain)}  # 1 = có mưa
            })

        # Cảnh báo
        if temp > 35:
            send_ids_alert("IOT_DATA_MANIPULATION", f"Nhiệt độ cao bất thường: {temp}°C từ {dev_id}", 80, data.get("seq_num", 0))
        if hum > 90:
            send_ids_alert("IOT_DATA_MANIPULATION", f"Độ ẩm cực cao: {hum}% từ {dev_id}", 70, data.get("seq_num", 0))

    elif dev_id == "esp32_multi2":
        gas = data.get("gas_level")
        light = data.get("light_level")

        if gas is not None:
            sensors.append({
                "sensorUid": f"{dev_id}_mq2",
                "type": "GAS_LPG",
                "data": {"gas_level": int(gas)}
            })
        if light is not None:
            sensors.append({
                "sensorUid": f"{dev_id}_ldr",
                "type": "LIGHT",
                "data": {"light_level": int(light)}
            })

        if gas is not None and gas > 2000:
            send_ids_alert("IOT_DEVICE_HIJACKING", f"Khí gas nguy hiểm: {gas} từ {dev_id}", 95, data.get("seq_num", 0))

    elif dev_id == "esp32_multi3":
        temp = data.get("temperature")
        hum = data.get("humidity")
        gas = data.get("gas_level")

        if temp is not None and temp > -999:
            sensors.append({
                "sensorUid": f"{dev_id}_dht_temp",
                "type": "TEMPERATURE",
                "data": {"temperature": round(temp, 1)}
            })
        if hum is not None and hum > -999:
            sensors.append({
                "sensorUid": f"{dev_id}_dht_hum",
                "type": "HUMIDITY",
                "data": {"humidity": round(hum, 1)}
            })
        if gas is not None:
            sensors.append({
                "sensorUid": f"{dev_id}_mq2",
                "type": "GAS_LPG",
                "data": {"gas_level": int(gas)}
            })

        if temp is not None and temp > 35:
            send_ids_alert("IOT_DATA_MANIPULATION", f"Nhiệt độ cao: {temp}°C từ {dev_id}", 85, data.get("seq_num", 0))
        if gas is not None and gas > 2000:
            send_ids_alert("IOT_DEVICE_HIJACKING", f"Nồng độ gas nguy hiểm: {gas} từ {dev_id}", 95, data.get("seq_num", 0))

    else:
        print(f"Device không xác định: {dev_id} → bỏ qua")
        return

    if not sensors:
        print(f"Không có dữ liệu cảm biến hợp lệ từ {dev_id}")
        return

    # Payload gửi lên backend – THÊM rawData để gửi đầy đủ
    payload = {
        "deviceUid": GATEWAY_UID,
        "timestamp": timestamp_ms,
        "sensors": sensors,
        "sequenceNumber": data.get("seq_num", 0),
        "sourceIp": data.get("dev_ip", "unknown"),
        "rssi": data.get("rssi", 0),
        "rawData": data  # ← Dòng duy nhất thêm vào payload
    }

    payload["checksum"] = calculate_checksum(payload)

    # THÊM DÒNG IN ĐẸP CHO GÓI TIN GỬI LÊN
    print_packet(f"GATEWAY→{dev_id}", "SENT", data.get("seq_num", 0), payload)

    # GỬI VÀ KIỂM TRA RESPONSE CHI TIẾT (KHÔNG ẢNH HƯỞNG HÀM KHÁC)
    try:
        response = requests.post(API_SENSOR_DATA, json=payload, timeout=15, verify=False)

        if response.status_code in [200, 201]:
            print(f"{'':>10}\033[92m[SERVER] ĐÃ NHẬN THÀNH CÔNG\033[0m", end="")
            try:
                res = response.json()
                anomaly = res.get("data", {}).get("anomalyDetected", False)
                sid = res.get("data", {}).get("sensorDataId", "N/A")
                print(f" | ID: {sid} | Anomaly: {anomaly}")
            except:
                print(" (không parse được JSON)")
        else:
            print(f"{'':>10}\033[91m[SERVER] LỖI {response.status_code}\033[0m → {response.text[:150]}")

    except requests.exceptions.Timeout:
        print(f"{'':>10}\033[91m[SERVER] TIMEOUT\033[0m")
    except Exception as e:
        print(f"{'':>10}\033[91m[SERVER] LỖI: {e}\033[0m")

# ==================== IDS ALERT (GIỮ NGUYÊN HOÀN TOÀN) ====================
def send_ids_alert(attack_type, description, severity, seq_num):
    alert_uid = str(uuid.uuid4())[:8]
    payload = {
        "deviceUid": GATEWAY_UID,
        "alertUid": f"ALERT_{alert_uid}",
        "attackType": attack_type,
        "severity": severity,
        "confidence": 0.92,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "sequenceNumber": seq_num,
        "signature": hashlib.md5(f"{GATEWAY_UID}{alert_uid}{seq_num}".encode()).hexdigest(),
        "sourceIp": "192.168.4.x",
        "ruleDescription": description
    }

    print(f"[IDS] → Cảnh báo: {attack_type} - {description}")
    try:
        requests.post(API_IDS_ALERT, json=payload, timeout=10, verify=False)
    except:
        pass

# ==================== MAIN (GIỮ NGUYÊN) ====================
def main():
    print("\n" + "="*70)
    print("IOT GATEWAY - ĐA CẢM BIẾN (esp32_multi1/2/3 + Proxy MQTT)")
    print("="*70)

    if not register_gateway():
        return

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"\nKết nối MQTT broker {MQTT_BROKER}:{MQTT_PORT}...")
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    except Exception as e:
        print(f"Không kết nối được broker: {e}")
        return

    print("\nGateway đã chạy! Đang lắng nghe các ESP32...")
    print("Nhấn Ctrl+C để dừng\n")

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nDừng gateway. Tạm biệt!")
        client.disconnect()

if __name__ == "__main__":
    main()