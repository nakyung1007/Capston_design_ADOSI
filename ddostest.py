import pandas as pd
from joblib import load
from sklearn import preprocessing

def attack_detection(json_path):
    # 데이터 불러오기
    data = pd.read_json(json_path).fillna(0)

    # 필요한 특성만 선택하여 데이터 준비
    df = data.dropna()

    # "Protocol" 열을 숫자로 변환
    protocol_map = {'TCP': 6, 'UDP': 17}  # 원하는 프로토콜 및 해당 숫자로 매핑
    df['Protocol'] = df['Protocol'].map(protocol_map)

    # 저장된 모델 불러오기
    loaded_model = load('/Users/chonakyung/modelmodel/ddos_detection_model.joblib')
    scaler = load('/Users/chonakyung/Desktop/capstone/packet/scaler.joblib')

    # 특성 이름 정의
    feature_names = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 
        'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count', 
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
        'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 
        'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Protocol'
    ]

    # 예측할 데이터
    sample_data = df[feature_names]

    # 예측할 데이터의 열 순서를 학습할 때 사용된 순서와 동일하게 만들기
    sample_data = sample_data.reindex(columns=scaler.feature_names_in_, fill_value=0)
    
    # 스케일러로 학습 데이터처럼 변환
    sample_data_scaled = scaler.transform(sample_data)

    # 모델에 예측 수행
    prediction = loaded_model.predict(sample_data_scaled)
    print("Prediction:", prediction)

    return prediction

# 예제 사용
json_path = '/Users/chonakyung/modelmodel/packet_info.json'
# json_path = 'normal_json/1.json'

predictions = attack_detection(json_path)
# 예제 사용
# if __name__ == "__main__":
#     json_path = '/Users/chonakyung/modelmodel/packet_info.json'
#     predictions = attack_detection(json_path)
#     print(predictions)
