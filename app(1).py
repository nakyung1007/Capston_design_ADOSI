import os
import pymysql
import pymysql.cursors
import logging
import random
import time
import threading
import subprocess
import pandas as pd
from joblib import load
from flask import Flask, request, session, redirect, render_template, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from collections import deque
import pyshark
import numpy as np

from Database.models import db, Fcuser, UserCity
from Database.MySQL import save_login_info_mysql, save_location_mysql, user_data, ip_data, validation_ip_data, attack_data
from Database.sqlite import save_login_info_sqlite, save_clicked_city
from forms import RegisterForm, LoginForm
from validation import get_user_location, calculate_distance, find_closest_city
from map import executor, cities, get_weather

# Flask 애플리케이션 생성
app = Flask(__name__)

# Flask 애플리케이션을 실행하는 파일의 경로
current_directory = os.path.abspath(os.path.dirname(__file__))

# 로깅 설정
logging.basicConfig(filename='app.log', level=logging.INFO)

# 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소 설정
ip_address = '172.30.1.56'
port = 5050

# 캡처할 패킷 필터 설정
capture_filter = f'ip src {ip_address}'

# 한 번에 캡처할 패킷 수 설정
capture_count = 500  # 예시 값, 필요한 만큼 설정

# 사전 학습된 모델과 스케일러 로드
model = load('/Users/chonakyung/modelmodel/ddos_detection_model.joblib')
scaler = load('/Users/chonakyung/Desktop/capstone/packet/scaler.joblib')

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

# 주기적으로 검증 아이피 목록 업데이트
# def update_validation_ips():
#     global validation_ips
#     while True:
#         validation_ips = validation_ip_data()
#         time.sleep(10)

# update_thread = threading.Thread(target=update_validation_ips)
# update_thread.daemon = True
# update_thread.start()

# 디도스 공격 감지
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

    # with open('/Users/chonakyung/modelmodel/packet_info.json', 'w') as json_file:
    #     json.dump(packet_info_list, json_file, indent=4)

    # print(f"{capture_count}개의 패킷 캡처 및 저장이 완료되었습니다.")
    # print(f"JSON 파일에 저장된 패킷 개수: {len(packet_info_list)}")

    # return packet_info_list
    try:
        with open('/Users/chonakyung/modelmodel/packet_info.json', 'w') as json_file:
            json.dump(packet_info_list, json_file, indent=4)
        print(f"{capture_count}개의 패킷 캡처 및 저장이 완료되었습니다.")
        print(f"JSON 파일에 저장된 패킷 개수: {len(packet_info_list)}")
    except Exception as e:
        print(f"JSON 파일 저장 중 오류 발생: {e}")

    return packet_info_list

def predict_attack(packet_info_list):
    protocol_map = {'TCP': 6, 'UDP': 17}
    for packet_info in packet_info_list:
        if packet_info['Protocol'] in protocol_map:
            packet_info['Protocol'] = protocol_map[packet_info['Protocol']]

    features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 
        'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count', 
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
        'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 
        'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Protocol'
    ]

    df = pd.DataFrame(packet_info_list, columns=features)
    sample_data = df.reindex(columns=scaler.feature_names_in_, fill_value=0)
    sample_data_scaled = scaler.transform(sample_data)

    prediction = model.predict(sample_data_scaled)
    print("Prediction:", prediction)
    return prediction

def main():
    while True:
        packet_info_list = capture_packets()
        if packet_info_list:
            predict_attack(packet_info_list)
        time.sleep(5)  # 5초마다 패킷 캡처 및 예측 수행



# def attack_detection(packet_info_list):
#     protocol_map = {'TCP': 6, 'UDP': 17}
#     for packet_info in packet_info_list:
#         if packet_info['Protocol'] in protocol_map:
#             packet_info['Protocol'] = protocol_map[packet_info['Protocol']]

#     features = [
#         'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s', 
#         'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count', 
#         'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
#         'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 
#         'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Protocol'
#     ]
#     df = pd.DataFrame(packet_info_list, columns=features)
#     sample_data = df.reindex(columns=scaler.feature_names_in_, fill_value=0)
#     sample_data_scaled = scaler.transform(sample_data)

#     prediction = model.predict(sample_data_scaled)
#     print("Prediction:", prediction)
#     return prediction

# def is_attack_detected():
#     packet_info_list = capture_packet()
#     if not packet_info_list:
#         return []
#     predictions = attack_detection(packet_info_list)
#     return predictions

# def periodic_prediction():
#     while True:
#         predictions = is_attack_detected()
#         if predictions and all(pred == 1 for pred in predictions):
#             logging.warning("DDoS attack detected!")
#         else:
#             logging.info("No DDoS attack detected.")
#         time.sleep(10)  # 주기적으로 예측 수행 (10초마다)

# predict_thread = threading.Thread(target=periodic_prediction)
# predict_thread.daemon = True
# predict_thread.start()

# 메인 화면
@app.route('/')
def hello():
    # 세션에 저장된 사용자 ID
    userid = session.get('userid', None)
    # 클라이언트 IP 주소 가져오기
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    # 클라이언트가 요청한 나라 정보 가져오기
    city_name = request.args.get('city')
    # 현재 시간을 포맷팅
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    latitude, longitude = get_user_location(client_ip)
    
    # 클라이언트가 도시 정보를 요청한 경우에만 로그를 기록
    if city_name:
        # 로그 기록
        log_message = f"[{timestamp}] '{userid}'가 '{client_ip}'에서 '{city_name}'를 클릭했습니다."
        logging.info(log_message)
    
    # 가까운 도시 찾기
    closest_city = find_closest_city(client_ip, cities)
    
    if city_name == closest_city:
        is_closest = True
    else:
        is_closest = False

    save_clicked_city(userid, client_ip, latitude, longitude, city_name, is_closest)
    
    return render_template('hello.html', userid=userid, client_ip=client_ip, city_name=city_name)

# 회원 가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
       fcuser = Fcuser() 
       fcuser.userid = form.data.get('userid')
       fcuser.username = form.data.get('username')
       fcuser.password = form.data.get('password')
       
       db.session.add(fcuser)
       db.session.commit()
       
       flash("가입 완료", 'success')
       
       return render_template('hello.html', form=form)
    return render_template('register.html', form=form)

# 로그인
@app.route('/login',  methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        userid = form.data.get('userid') 
        session['userid'] = userid
        ip_address = request.remote_addr
        
        # SQLite에 저장
        save_login_info_sqlite(userid, ip_address)
        
        # MySQL에 저장
        save_login_info_mysql(userid, ip_address)
        
        # 만약 관리자로 로그인한 경우에는 세션에 admin이라는 키를 추가
        if userid == "admin":
            session['admin'] = True
        return redirect('/')
    return render_template('login.html', form=form)

# 로그아웃
@app.route('/logout', methods=['GET'])
def logout():
    if 'userid' in session:
        userid = session.pop('userid')
        flash('로그아웃 되었습니다.', 'success')
        
        session.pop('admin', None)
    return redirect('/')

# 관리자 페이지
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # 세션에 저장된 사용자 ID
    userid = session.get('userid', None)
    
    # 디도스 공격을 감지하면 경고 메시지를 플레시 메시지로 저장
    if is_attack_detected():
        flash('디도스 공격이 감지되었습니다. 서비스 이용이 제한될 수 있습니다.', 'danger')
        ddos = True
    else:
        ddos = False
    
    if 'admin' in session:
        user_table = user_data()
        ip_table = ip_data()
    else:
        flash('관리자만 접근할 수 있는 페이지입니다.', 'danger')
        return redirect('/')
    return render_template('admin.html', userid=userid, ddos=ddos, user_data=user_table, ip_data=ip_table)

# 지도
@app.route('/map')
def map():
    userid = session.get('userid', None)
    
    cities = [
    {"name": "서울", "lat": 37.5665, "lon": 126.9780},
    {"name": "파리", "lat": 48.8566, "lon": 2.3522},
    {"name": "뉴욕", "lat": 40.7128, "lon": -74.0060},
    {"name": "리우데자네이루", "lat": -22.9068, "lon": -43.1729},
    {"name": "카이로", "lat": 30.0444, "lon": 31.2357},
    {"name": "시드니", "lat": -33.8688, "lon": 151.2093}
    ]
    
    weather_data = list(executor.map(get_weather, cities))
    
    return render_template('map.html', weather_data=weather_data, userid=userid)

@app.route('/clicked_city_info')
def clicked_city_info():
    # 클라이언트의 IP 주소 가져오기
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    # 클라이언트의 위치 정보 가져오기
    client_latitude, client_longitude = get_user_location(client_ip)
    # 가장 가까운 도시 찾기
    closest_city = find_closest_city(client_ip, cities)
    # 클릭한 도시 정보 가져오기
    clicked_city_info = UserCity.query.filter_by(client_ip=client_ip, clicked_city=closest_city).first()
    
    # UserCity 테이블에서 모든 데이터 가져오기
    all_user_city_data = UserCity.query.all()
    
    return render_template('clicked_city_info.html', client_latitude=client_latitude, client_longitude=client_longitude, closest_city=closest_city, clicked_city_info=clicked_city_info, all_user_city_data=all_user_city_data)

# 게임
@app.route('/game', methods=['GET', 'POST'])
def rsp_game():
    userid = session.get('userid', None)
        
    if request.method == 'POST':
        # 클라이언트로부터 받은 선택
        player_choice = request.form.get('choice')
        
        # 서버에서 선택
        choices = ['Rock', 'Paper', 'Scissors']
        computer_choice = random.choice(choices)
        
        # 결과 계산
        if player_choice == computer_choice:
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 비겼습니다!"
        elif (player_choice == "Rock" and computer_choice == "Scissors") or \
             (player_choice == "Scissors" and computer_choice == "Paper") or \
             (player_choice == "Paper" and computer_choice == "Rock"):
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 이겼습니다!"
        else:
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 졌습니다!"

        # 로그에 사용자와 컴퓨터의 선택 기록
        if userid:
            logging.info(f"{userid}님이 {player_choice}을(를) 선택하였습니다.")
            logging.info(f"컴퓨터가 {computer_choice}을(를) 선택하였습니다.")
        elif userid == None:
            logging.info(f"사용자가 {player_choice}을(를) 선택하였습니다.")
            logging.info(f"컴퓨터가 {computer_choice}을(를) 선택하였습니다.")
        
        # 결과를 클라이언트에게 전송하고 로그에 기록
        response = {'result': result}
        logging.info(result)
        return jsonify(response)

    # GET 요청에 대한 응답
    return render_template('rsp_game.html', userid=userid)

# 메인 함수    
if __name__ == "__main__":
    basedir = os.path.abspath(os.path.dirname(__file__))
    dbfile = os.path.join(basedir, 'db.sqlite')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbfile
    app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'wcsfeufhwiquehfdx'
        
    db.init_app(app)
    db.app = app
    with app.app_context():
        db.create_all()

    # # 백그라운드에서 packet_test.py 실행
    # subprocess.Popen(["python", "/Users/chonakyung/modelmodel/packet_test.py"])
    # 백그라운드에서 패킷 캡처 및 예측 수행
    packet_capture_thread = threading.Thread(target=main)
    packet_capture_thread.daemon = True
    packet_capture_thread.start()

    
    app.run(host='0.0.0.0', port="5050", debug=True)