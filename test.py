import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, classification_report
from joblib import load
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
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import load
from Database.models import db, Fcuser, UserCity
from Database.sqlite import save_login_info_sqlite, save_clicked_city
from forms import RegisterForm, LoginForm
from attack import detect_dos_attack
from validation import get_user_location, calculate_distance, find_closest_city
from map import executor, cities, get_weather
from werkzeug.serving import WSGIRequestHandler

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
model = load('/Users/chonakyung/modelmodel/DDOS_model (1).joblib')
scaler = load('/Users/chonakyung/modelmodel/scaler (3).joblib')

# 예시 비정상 데이터 생성
abnormal_data = pd.DataFrame({
    'Flow Duration': [1000000, 2000000, 3000000],
    'Total Fwd Packets': [10, 20, 30],
    'Total Backward Packets': [5, 10, 15],
    'Flow Packets/s': [1.5, 2.5, 3.5],
    'Flow Bytes/s': [1500, 2500, 3500],
    'Avg Packet Size': [500, 600, 700],
    'FIN Flag Count': [1, 1, 1],
    'SYN Flag Count': [1, 1, 1],
    'RST Flag Count': [0, 0, 0],
    'PSH Flag Count': [1, 1, 1],
    'ACK Flag Count': [1, 1, 1],
    'URG Flag Count': [0, 0, 0],
    'ECE Flag Count': [0, 0, 0],
    'Fwd Packets Length Total': [1000, 2000, 3000],
    'Bwd Packets Length Total': [500, 1000, 1500],
    'Flow IAT Mean': [0.5, 0.6, 0.7],
    'Flow IAT Std': [0.1, 0.2, 0.3],
    'Idle Mean': [0.5, 0.6, 0.7],
    'Protocol': [6, 6, 6]
})

# 데이터 스케일링
abnormal_data_scaled = scaler.transform(abnormal_data)

# 예측
predictions = model.predict(abnormal_data_scaled)
print("Predictions for abnormal data:", predictions)
