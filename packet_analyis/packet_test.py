import pyshark
import json
import numpy as np
import time
from collections import deque

# 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소 설정
ip_address = '172.30.1.56'
port = 5050

# 캡처할 패킷 필터 설정
capture_filter = f'ip src {ip_address}'

# 한 번에 캡처할 패킷 수 설정
capture_count = 500  # 예시 값, 필요한 만큼 설정

def mac_to_int64(mac):
    return int(mac.replace(':', ''), 16)

def extract_flags(tcp_layer):
    def get_flag_value(flag):
        value = tcp_layer.get_field_value(flag)
        return 1 if value == 'True' else 0

    flags = {
        'FIN': get_flag_value('flags_fin'),
        'SYN': get_flag_value('flags_syn'),
        'RST': get_flag_value('flags_reset'),
        'PSH': get_flag_value('flags_push'),
        'ACK': get_flag_value('flags_ack'),
        'URG': get_flag_value('flags_urg'),
        'ECE': get_flag_value('flags_ecn')
    }
    return flags

def capture_packets():
    packet_info_list = []

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)
    iat_times = deque(maxlen=capture_count)

    for packet in capture.sniff_continuously(packet_count=capture_count):
        if 'IP' in packet:
            ip_layer = packet.ip
            tcp_layer = packet.tcp if hasattr(packet, 'tcp') else None

            flags = extract_flags(tcp_layer) if tcp_layer else {}

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

            packet_info_list.append(packet_info)

            if len(packet_info_list) >= capture_count:
                break

    with open('/Users/chonakyung/modelmodel/packet_info.json', 'w') as json_file:
        json.dump(packet_info_list, json_file, indent=4)

    print(f"{capture_count}개의 패킷 캡처 및 저장이 완료되었습니다.")
    print(f"JSON 파일에 저장된 패킷 개수: {len(packet_info_list)}")

def main():
    while True:
        capture_packets()
        time.sleep(5)  # 5초마다 패킷 캡처, 필요에 따라 조정 가능

if __name__ == "__main__":
    main()

