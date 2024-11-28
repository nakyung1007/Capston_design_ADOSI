import pyshark
import json
import sys
from datetime import datetime

threshold_value = 100  # 임계값 설정

# 캡처할 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소와 포트 설정
ip_address = '10.201.176.47'
port = '5050'

# 캡처할 패킷 필터 설정
capture_filter = f'tcp and ip src {ip_address} and port {port}'

# JSON 파일에 저장할 리스트 생성
packet_info_list = []

# 캡처할 패킷 수 설정
capture_count = 1000

# 패킷 캡처 및 처리
capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)

for packet in capture.sniff_continuously(packet_count=capture_count):
    try:
        # 패킷 정보 추출 및 가공
        packet_info = {        
                'dt': int(packet.sniff_time.timestamp()),  # datetime을 Unix timestamp로 변환
                'switch': int(packet.eth.src.replace(":", ""), 16),  # MAC 주소를 정수로 변환
                'src': getattr(packet, 'ip', None).src if hasattr(packet, 'ip') else None,
                'dst': getattr(packet, 'ip', None).dst if hasattr(packet, 'ip') else None,
                'pktcount': 1,
                'bytecount': len(packet),
                'dur': int(float(packet.frame_info.time_relative)),
                'dur_nsec': int(float(packet.sniff_timestamp) * 1e9),
                'tot_dur': float(packet.frame_info.time_delta),
                'flows': int(getattr(packet, 'tcp', 0).stream) if hasattr(packet, 'tcp') else 0,
                'packetins': int(getattr(packet.frame_info, 'packet_in', 0)),
                'pktperflow': int(packet.tcp.len) if hasattr(packet, 'tcp') else 0,
                'byteperflow': int(packet.ip.len) if hasattr(packet, 'ip') else 0,
                'pktrate': int(getattr(packet.frame_info, 'packet_rate', 0)),
                'Pairflow': int(packet.ip.dsfield_dscp) if hasattr(packet, 'ip') else 0,
                'Protocol': packet.transport_layer,
                'port_no': int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
                'tx_bytes': int(packet.ip.len) if hasattr(packet, 'ip') else 0,
                'rx_bytes': int(packet.ip.len) if hasattr(packet, 'ip') else 0,
                'tx_kbps': float(getattr(packet.frame_info, 'transport_layer', 0)),
                'rx_kbps': float(getattr(packet.frame_info, 'transport_layer', 0)),
                'tot_kbps': float(getattr(packet.frame_info, 'transport_layer', 0))
        }

        # JSON 리스트에 추가
        packet_info_list.append(packet_info)

        # 캡처할 패킷 수만큼 캡처한 후 종료
        if len(packet_info_list) >= capture_count:
            break
    except Exception as e:
        print(f"An error occurred while processing packet: {e}")

# JSON 파일로 저장
with open('packet_info.json', 'w') as json_file:
    json.dump(packet_info_list, json_file)

# 종료 메시지 출력
print("패킷 캡처 및 저장이 완료되었습니다.")

# 프로그램 종료
sys.exit(0)
