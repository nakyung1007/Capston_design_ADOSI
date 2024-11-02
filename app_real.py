import pyshark
import json
import sys
import threading
import numpy as np
import pandas as pd
from joblib import load
import time

# 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소 설정
ip_address = '172.30.1.38'
port = 5050

# 캡처할 패킷 필터 설정
capture_filter = f'host {ip_address} and port {port}'

# 캡처할 플라스크 서버 포트 설정 (예: 5000)
flask_server_port = 5050

# 캡처할 패킷 수 설정
capture_count = 50  # 예시 값, 필요한 만큼 설정

def extract_flags(tcp_layer):
    flags = {
        'FIN': 1 if tcp_layer.get_field_value('flags_fin') == '1' else 0,
        'SYN': 1 if tcp_layer.get_field_value('flags_syn') == '1' else 0,
        'RST': 1 if tcp_layer.get_field_value('flags_reset') == '1' else 0,
        'PSH': 1 if tcp_layer.get_field_value('flags_push') == '1' else 0,
        'ACK': 1 if tcp_layer.get_field_value('flags_ack') == '1' else 0,
        'URG': 1 if tcp_layer.get_field_value('flags_urg') == '1' else 0,
        'ECE': 1 if tcp_layer.get_field_value('flags_ecn') == '1' else 0,
    }
    return flags

# 모델과 스케일러 불러오기
model = load('/Users/chonakyung/modelmodel/model.joblib')
scaler = load('/Users/chonakyung/modelmodel/scaler (4).joblib')
label_encoder = load('/Users/chonakyung/modelmodel/encoder.joblib')

# 실시간 패킷 캡처 및 처리 함수
def capture_packets():
    packet_info_list = []
    
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)
    iat_times = []
    
    for packet in capture.sniff_continuously(packet_count=capture_count):
        if 'IP' in packet:
            ip_layer = packet.ip
            tcp_layer = packet.tcp if hasattr(packet, 'tcp') else None

            # 플래그 추출
            flags = extract_flags(tcp_layer) if tcp_layer else {}

            # 이전 패킷 시간과 현재 패킷 시간 차이 (IAT: Inter-Arrival Time)
            if 'last_time' in locals():
                iat = float(packet.sniff_time.timestamp()) - last_time
                iat_times.append(iat)
            last_time = float(packet.sniff_time.timestamp())

            packet_info = {
                'Flow Duration': int(float(packet.frame_info.time_relative) * 1e9),
                'Total Fwd Packets': int(1) if tcp_layer and tcp_layer.srcport == port else 0,
                'Total Backward Packets': int(1) if tcp_layer and tcp_layer.dstport == port else 0,
                'Flow Packets/s': float(packet.frame_info.time_delta) if hasattr(packet.frame_info, 'time_delta') else 0,
                'Flow Bytes/s': float(len(packet)) / float(packet.frame_info.time_delta) if hasattr(packet.frame_info, 'time_delta') and float(packet.frame_info.time_delta) > 0 else 0,
                'Avg Packet Size': float(len(packet)),
                'FIN Flag Count': flags.get('FIN', 0),
                'SYN Flag Count': flags.get('SYN', 0),
                'RST Flag Count': flags.get('RST', 0),
                'PSH Flag Count': flags.get('PSH', 0),
                'ACK Flag Count': flags.get('ACK', 0),
                'URG Flag Count': flags.get('URG', 0),
                'ECE Flag Count': flags.get('ECE', 0),
                'Fwd Packets Length Total': int(packet.length) if tcp_layer and tcp_layer.srcport == port else 0,
                'Bwd Packets Length Total': int(packet.length) if tcp_layer and tcp_layer.dstport == port else 0,
                'Flow IAT Mean': np.mean(iat_times) if iat_times else 0,
                'Flow IAT Std': np.std(iat_times) if iat_times else 0,
                'Idle Mean': np.mean(iat_times) if iat_times else 0,  # Assuming idle time is same as IAT for now
            }

            packet_info_list.append(packet_info)

            if len(packet_info_list) >= capture_count:
                break

    return packet_info_list

def attack_detection(packet_info_list):
    # 샘플 데이터를 판다스로 만들기
    features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 
        'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count', 
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
        'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 
        'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean'
    ]
    
    df = pd.DataFrame(packet_info_list, columns=features)
    sample_data = df.reindex(columns=scaler.feature_names_in_, fill_value=0)
    sample_data_scaled = scaler.transform(sample_data)

    predicted_labels = model.predict(sample_data_scaled)
    decoded_labels = label_encoder.inverse_transform(predicted_labels)
    print("Decoded Labels:", decoded_labels)
    
    return decoded_labels

def main():
    while True:
        packet_info_list = capture_packets()
        if packet_info_list:
            attack_detection(packet_info_list)
        time.sleep(1)  # 1초마다 패킷 캡처 및 예측 수행

if __name__ == "__main__":
    main()