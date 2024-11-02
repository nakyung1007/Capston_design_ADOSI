# 필요한 라이브러리를 가져옵니다.
import pyshark
import json
import os
from datetime import datetime

def analyze_packets(interface, target_host, target_port):
    filename = 'packet_analysis.json'

    # 파일이 존재하지 않으면 새로 생성하고, 존재하면 기존 파일에 추가합니다.
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            file.write('[')
            file.write('\n')
            pass  # 아무 작업도 수행하지 않음

    with open(filename, 'a') as file:
        capture = pyshark.LiveCapture(interface=interface, capture_filter=f'host {target_host} and port {target_port}')
        for packet in capture.sniff_continuously():
            if hasattr(packet, 'ip') and packet.ip.dst == target_host:
                packet_info = {
                    'dt': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),  # 패킷의 시간 스탬프
                    'switch': packet.eth.src,  # 스위치 번호 또는 식별자
                    'src': getattr(packet, 'ip', None).src if hasattr(packet, 'ip') else None,  # 송신지 IP 주소
                    'dst': getattr(packet, 'ip', None).dst if hasattr(packet, 'ip') else None,  # 수신지 IP 주소
                    'pktcount': 1,  # 수정: 단일 패킷이므로 1로 고정
                    'bytecount': len(packet),  # 수정: 패킷의 길이로 바꿈
                    'dur': packet.frame_info.time_relative,  # 패킷 전송에 걸린 시간(초)
                    'tot_dur': packet.frame_info.time_delta,  # 총 지속시간
                    'flows': getattr(packet, 'tcp', None).stream if hasattr(packet, 'tcp') else None,  # 수정: TCP 레이어가 있는 경우에만 가져오도록 변경
                    'packetins': getattr(packet.frame_info, 'packet_in', None),  # 예외 처리 추가
                    'pktperflow': packet.tcp.len if hasattr(packet, 'tcp') else None,  # 수정: TCP 레이어가 있는 경우에만 가져오도록 변경
                    'byteperflow': packet.ip.len if hasattr(packet, 'ip') else None,  # 수정: IP 레이어가 있는 경우에만 가져오도록 변경
                    'pktrate': getattr(packet.frame_info, 'packet_rate', None),  # 패킷 속도
                    'Pairflow': packet.ip.dsfield_dscp if hasattr(packet, 'ip') else None,  # 수정: IP 레이어가 있는 경우에만 가져오도록 변경
                    'Protocol': packet.transport_layer,  # 통신 프로토콜
                    'port_no': packet.tcp.srcport if hasattr(packet, 'tcp') else None,  # 수정: TCP 레이어가 있는 경우에만 가져오도록 변경
                    'tx_bytes': packet.ip.len if hasattr(packet, 'ip') else None,  # 수정: IP 레이어가 있는 경우에만 가져오도록 변경
                    'rx_bytes': packet.ip.len if hasattr(packet, 'ip') else None,  # 수정: IP 레이어가 있는 경우에만 가져오도록 변경
                    'tx_kbps': getattr(packet.frame_info, 'transport_layer', None),  # 예외 처리 추가
                    'rx_kbps': getattr(packet.frame_info, 'transport_layer', None),  # 예외 처리 추가
                    'tot_kbps': getattr(packet.frame_info, 'transport_layer', None),  # 예외 처리 추가
                }
                # JSON 데이터를 파일에 쓰고 새 줄에 작성합니다.
                json.dump(packet_info, file)
                file.write(', \n')
                yield packet_info

# analyze_packets 함수 호출
with open('packet_analysis.json', 'a') as file:
    for packet_info in analyze_packets("en0", "192.168.0.15", 5050):
        json.dump(packet_info, file)
        file.write(', \n')
        
with open('packet_analysis.json', 'a') as file:
    file.write(']')
