import pyshark
import pandas as pd
import numpy as np
import time
from joblib import load
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소 설정
ip_address = '192.168.0.12'
port = 5050

# 모델 클래스 정의
class Model:
    def __init__(self, data, labels):
        self.data = data
        self.y = labels
        self.scaler = StandardScaler().fit(self.data)
        X = self.scaler.transform(self.data)
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(X, self.y, random_state=42, test_size=0.3)
        self.RF = None

    def RandomForest(self):
        start_time = time.time()
        self.RF = RandomForestClassifier(
            criterion='gini', n_estimators=500, min_samples_split=10, max_features='sqrt', 
            oob_score=True, random_state=1, n_jobs=-1
        ).fit(self.X_train, self.y_train)

        predicted_rf = self.RF.predict(self.X_test)
        rf_accuracy = accuracy_score(self.y_test, predicted_rf)
        print(f"Accuracy of RF is : {round(rf_accuracy * 100, 2)}%", '\n')
        print("########################################################################")
        print(classification_report(predicted_rf, self.y_test))
        print("########################################################################")
        print(" = = %s seconds = = " % (time.time() - start_time))

    def predict(self, sample_data):
        loaded_scaler = load('/Users/chonakyung/modelmodel/scaler (3).joblib')
        new_data = loaded_scaler.transform(sample_data)
        predicted_labels = self.RF.predict(new_data)
        return predicted_labels
    
# 모델과 스케일러 불러오기
model_path = '/Users/chonakyung/modelmodel/packet/DDOS_model (1).joblibb'
try:
    model = load(model_path)
except AttributeError as e:
    print(f"Error loading model: {e}")

scaler = load('/Users/chonakyung/modelmodel/scaler (3).joblib')

# 실시간 패킷 캡처 및 처리 함수
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

def capture_and_predict_packets(interface, ip_address, port, capture_count=500):
    while True:
        try:
            capture_filter = f'ip src {ip_address}'
            capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)
            iat_times = []
            packet_infos = []
            
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
                        'Protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else None
                    }
                    packet_infos.append(packet_info)

            protocol_map = {'TCP': 6, 'UDP': 17}
            for packet_info in packet_infos:
                if packet_info['Protocol'] in protocol_map:
                    packet_info['Protocol'] = protocol_map[packet_info['Protocol']]

            features = [
                'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s',
                'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count',
                'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
                'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total',
                'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Protocol'
            ]

            sample_data = pd.DataFrame(packet_infos, columns=features)
            sample_data = sample_data.reindex(columns=scaler.feature_names_in_, fill_value=0)
            sample_data_scaled = scaler.transform(sample_data)

            predictions = model.predict(sample_data_scaled)

            # 터미널에 예측 결과 출력
            print(f"Predictions: {predictions}")

            # 일정 시간 대기 후 다시 캡처 시작
            time.sleep(1)
        except Exception as e:
            print(f"Error during packet capture and prediction: {e}")
            time.sleep(5)

# 패킷 캡처 및 예측 시작
capture_and_predict_packets(interface, ip_address, port)
