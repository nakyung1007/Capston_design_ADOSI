import json

# JSON 파일 경로
json_path = '/Users/chonakyung/modelmodel/packet_info.json'

# JSON 파일에서 데이터를 읽어들이기
with open(json_path, 'r') as file:
    packet_data = json.load(file)

# 데이터 출력
print(json.dumps(packet_data, indent=4))
