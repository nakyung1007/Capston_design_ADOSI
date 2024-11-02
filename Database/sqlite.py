import logging
from flask import flash
from Database.models import db, Fcuser, LoginLog, UserCity
from datetime import datetime

# db.sqlite에 로그인 정보 저장
def save_login_info_sqlite(userid, ip_address):
    try:
        login_log = LoginLog(userid=userid, ip_address=ip_address)
        db.session.add(login_log)
        db.session.commit()
        # flash("로그인 정보가 SQLite에 저장되었습니다.", "success")
    except Exception as e:
        flash(f"SQLite에 로그인 정보를 저장하는 동안 오류가 발생했습니다. {e}", "danger")
        logging.error(f"SQLite에 사용자 정보 저장 중 오류 발생: {e}")
        
# SQLite에 사용자가 클릭한 도시 정보 저장
def save_clicked_city(userid, client_ip, latitude, longitude, clicked_city, is_closest):
    try:
        if clicked_city is not None:
            if userid is None:
                userid = 'None'
            user_city = UserCity(userid=userid, client_ip=client_ip, latitude=latitude, longitude=longitude, clicked_city=clicked_city, is_closest=is_closest)
            db.session.add(user_city)
            db.session.commit()
            flash("클릭한 도시 정보가 저장되었습니다.", "success")
    except Exception as e:
        flash(f"클릭한 도시 정보를 저장하는 동안 오류가 발생했습니다.")
        logging.error(f"클릭한 도시 정보 저장 중 오류 발생: {e}")