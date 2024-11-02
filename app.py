import os
import pymysql
import pymysql.cursors
import logging
import random
import time
import threading
import pyshark
import csv
import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from flask import Flask, request, session, redirect, render_template, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
from matplotlib.pyplot import figure

from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn import preprocessing

import time

from sklearn.ensemble import RandomForestClassifier

from joblib import dump
import joblib



from joblib import load
from Database.models import db, Fcuser, UserCity
from Database.sqlite import save_login_info_sqlite, save_clicked_city
from forms import RegisterForm, LoginForm
from attack import detect_dos_attack
from validation import get_user_location, calculate_distance, find_closest_city
from map import executor, cities, get_weather


# Flask 애플리케이션 생성
app = Flask(__name__)

# 로깅 설정
logging.basicConfig(filename='app.log', level=logging.INFO)

# 모델과 스케일러 불러오기
#model = load('/Users/chonakyung/modelmodel/DDOS_model (1).joblib')
#scaler = load('/Users/chonakyung/modelmodel/scaler .joblib')

# 네트워크 인터페이스 선택
interface = 'en0'

# 캡처할 IP 주소 설정
ip_address = '172.30.1.38'
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
        loaded_scaler = load('/Users/chonakyung/조선대학교/2024-1/캡스톤디자인/modelmodel/New_scaler.joblib')
        new_data = loaded_scaler.transform(sample_data)
        predicted_labels = self.RF.predict(new_data)
        return predicted_labels
    
# 모델과 스케일러 불러오기
model_path = '/Users/chonakyung/조선대학교/2024-1/캡스톤디자인/modelmodel/Classification_model (1).joblib'
try:
    model = joblib.load(model_path)
except AttributeError as e:
    print(f"Error loading model: {e}")

scaler = joblib.load('/Users/chonakyung/조선대학교/2024-1/캡스톤디자인/modelmodel/New_scaler.joblib')

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


    #         last_time = float(packet.sniff_time.timestamp())

    #         packet_info = {
    #             'Flow Duration': int(float(packet.frame_info.time_relative) * 1e9),
    #             'Total Fwd Packets': int(1) if tcp_layer and tcp_layer.srcport == port else 0,
    #             'Total Backward Packets': int(1) if tcp_layer and tcp_layer.dstport == port else 0,
    #             'Flow Packets/s': float(packet.frame_info.time_delta) if hasattr(packet.frame_info, 'time_delta') else 0,
    #             'Flow Bytes/s': float(len(packet)) / float(packet.frame_info.time_delta) if hasattr(packet.frame_info, 'time_delta') and float(packet.frame_info.time_delta) > 0 else 0,
    #             'Avg Packet Size': float(len(packet)),
    #             'FIN Flag Count': flags.get('FIN', 0),
    #             'SYN Flag Count': flags.get('SYN', 0),
    #             'RST Flag Count': flags.get('RST', 0),
    #             'PSH Flag Count': flags.get('PSH', 0),
    #             'ACK Flag Count': flags.get('ACK', 0),
    #             'URG Flag Count': flags.get('URG', 0),
    #             'ECE Flag Count': flags.get('ECE', 0),
    #             'Fwd Packets Length Total': int(packet.length) if tcp_layer and tcp_layer.srcport == port else 0,
    #             'Bwd Packets Length Total': int(packet.length) if tcp_layer and tcp_layer.dstport == port else 0,
    #             'Flow IAT Mean': np.mean(iat_times) if iat_times else 0,
    #             'Flow IAT Std': np.std(iat_times) if iat_times else 0,
    #             'Idle Mean': np.mean(iat_times) if iat_times else 0,  # Assuming idle time is same as IAT for now
    #             'Protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else None
    #         }
    #         packet_infos.append(packet_info)

    # protocol_map = {'TCP': 6, 'UDP': 17}
    # for packet_info in packet_infos:
    #     if packet_info['Protocol'] in protocol_map:
    #         packet_info['Protocol'] = protocol_map[packet_info['Protocol']]

    # features = [
    #     'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Packets/s',
    #     'Flow Bytes/s', 'Avg Packet Size', 'FIN Flag Count', 'SYN Flag Count',
    #     'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    #     'ECE Flag Count', 'Fwd Packets Length Total', 'Bwd Packets Length Total',
    #     'Flow IAT Mean', 'Flow IAT Std', 'Idle Mean', 'Protocol'
    # ]

    # sample_data = pd.DataFrame(packet_infos, columns=features)
    # sample_data = sample_data.reindex(columns=scaler.feature_names_in_, fill_value=0)
    # sample_data_scaled = scaler.transform(sample_data)

    # predictions = model.predict(sample_data_scaled)
    #  # 터미널에 예측 결과 출력
    # print(f"Predictions: {predictions}")

    # time.sleep(1)

@app.route('/analyze_packets', methods=['GET'])
def analyze_packets():
    predictions = capture_and_predict_packets(interface, ip_address, port)
    return f"Predictions: {predictions}"

# 메인 화면
@app.route('/')
def hello():
    userid = session.get('userid', None)
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    city_name = request.args.get('city')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    latitude, longitude = get_user_location(client_ip)
    
    if city_name:
        log_message = f"[{timestamp}] '{userid}'가 '{client_ip}'에서 '{city_name}'를 클릭했습니다."
        logging.info(log_message)
    
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
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        userid = form.data.get('userid') 
        session['userid'] = userid
        ip_address = request.remote_addr
        
        save_login_info_sqlite(userid, ip_address)
        
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
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    client_latitude, client_longitude = get_user_location(client_ip)
    closest_city = find_closest_city(client_ip, cities)
    clicked_city_info = UserCity.query.filter_by(client_ip=client_ip, clicked_city=closest_city).first()
    all_user_city_data = UserCity.query.all()
    
    return render_template('clicked_city_info.html', client_latitude=client_latitude, client_longitude=client_longitude, closest_city=closest_city, clicked_city_info=clicked_city_info, all_user_city_data=all_user_city_data)

# 게임
@app.route('/game', methods=['GET', 'POST'])
def rsp_game():
    userid = session.get('userid', None)
        
    if request.method == 'POST':
        player_choice = request.form.get('choice')
        
        choices = ['Rock', 'Paper', 'Scissors']
        computer_choice = random.choice(choices)
        
        if player_choice == computer_choice:
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 비겼습니다!"
        elif (player_choice == "Rock" and computer_choice == "Scissors") or \
             (player_choice == "Scissors" and computer_choice == "Paper") or \
             (player_choice == "Paper" and computer_choice == "Rock"):
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 이겼습니다!"
        else:
            result = f"컴퓨터의 선택은 [{computer_choice}]\n 졌습니다!"

        if userid:
            logging.info(f"{userid}님이 {player_choice}을(를) 선택하였습니다.")
            logging.info(f"컴퓨터가 {computer_choice}을(를) 선택하였습니다.")
        elif userid == None:
            logging.info(f"사용자가 {player_choice}을(를) 선택하였습니다.")
            logging.info(f"컴퓨터가 {computer_choice}을(를) 선택하였습니다.")
        
        response = {'result': result}
        logging.info(result)
        return jsonify(response)

    return render_template('rsp_game.html', userid=userid)

def start_packet_capture():
    capture_and_predict_packets(interface, ip_address, port)

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

    # 패킷 캡처 스레드 시작
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.daemon = True
    capture_thread.start()

    
    app.run(host='0.0.0.0', port="5050", debug=True)