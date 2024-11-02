import pymysql, pymysql.cursors, logging, time, threading
from datetime import datetime
from flask import Flask, request, redirect, render_template, session, flash, jsonify, abort
from validation import get_user_location, calculate_distance, find_closest_city

# User 테이블 데이터 가져오기
def user_data():
    DB = pymysql.connect(host='localhost', user='root', passwd='nakyung369', db='DDoS', charset='utf8')
    cursor = DB.cursor()
    sql = "SELECT * FROM DDoS.User"
    cursor.execute(sql)
    result = cursor.fetchall()
    DB.close()
    return result

# Attack 테이블 데이터 가져오기
def attack_data():
    DB = pymysql.connect(host='localhost', user='root', passwd='nakyung369', db='DDoS', charset='utf8')
    cursor = DB.cursor()
    sql = "SELECT * FROM DDoS.Attacks"
    cursor.execute(sql)
    result = cursor.fetchall()
    DB.close()
    return result

# Validation_IP 테이블 데이터 가져오기
def ip_data():
    DB = pymysql.connect(host='localhost', user='root', passwd='nakyung369', db='DDoS', charset='utf8')
    cursor = DB.cursor()
    sql = "SELECT * FROM DDoS.Validation_IP"
    cursor.execute(sql)
    result = cursor.fetchall()
    DB.close()
    return result

# Validation_IP 데이터 가져오기
def validation_ip_data():
    DB = pymysql.connect(host='localhost', user='root', passwd='nakyung369', db='DDoS', charset='utf8')
    cursor = DB.cursor()
    sql = "SELECT validation_ip FROM DDoS.Validation_IP"
    cursor.execute(sql)
    result = [row[0] for row in cursor.fetchall()]
    DB.close()
    return result

# MySQL에 로그인 정보 저장
def save_login_info_mysql(userid, ip_address):
    try:
        # MySQL 연결 설정
        connection = pymysql.connect(
            host='localhost',
            user='root',
            passwd='nakyung369',
            db='DDoS',
            charset='utf8'
        )

        with connection.cursor() as cursor:
            # INSERT 쿼리를 실행하여 사용자 로그인 정보를 저장
            sql = "INSERT INTO User (userid, ip_address, login_time) VALUES (%s, %s, %s)"
            login_time = datetime.now()
            cursor.execute(sql, (userid, ip_address, login_time))
            connection.commit()  # 변경 내용을 데이터베이스에 커밋
        # flash("로그인 정보가 MySQL에 저장되었습니다.", "success")
    except Exception as e:
        flash(f"MySQL에 로그인 정보를 저장하는 동안 오류가 발생했습니다. {e}", "danger")
        logging.error(f"MySQL에 사용자 정보 저장 중 오류 발생: {e}")
    finally:
        connection.close()  # 연결 종료
        
# MySQL에 위치 정보 저장
def save_location_mysql(userid, ip_address):
    try:
        # MySQL 연결 설정
        connection = pymysql.connect(
            host='localhost',
            user='root',
            passwd='nakyung369',
            db='DDoS',
            charset='utf8'
        )
        latitude, longitude = get_user_location(ip_address)
        
        with connection.cursor() as cursor:
            if userid is None:
                userid = 'None'
            sql = "INSERT INTO UserLocation (userid, ip_address, latitude, longitude) VALUES (%s, %s, %s, %s)"
            # login_time = datetime.now()
            cursor.execute(sql, (userid, ip_address, latitude, longitude))
            connection.commit()  # 변경 내용을 데이터베이스에 커밋
        # flash("로그인 정보가 MySQL에 저장되었습니다.", "success")
    except Exception as e:
        flash(f"MySQL에 로그인 정보를 저장하는 동안 오류가 발생했습니다. {e}", "danger")
        logging.error(f"MySQL에 사용자 정보 저장 중 오류 발생: {e}")
    finally:
        connection.close()  # 연결 종료