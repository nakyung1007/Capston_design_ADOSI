from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


db = SQLAlchemy()

class Fcuser(db.Model):
    __tablename__ = 'fcuser'
    id = db.Column(db.Integer, primary_key = True)
    password = db.Column(db.String(64))
    userid = db.Column(db.String(32))
    username = db.Column(db.String(8))
    ip_address = db.Column(db.String(64))
    

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.now)

class UserCity(db.Model):
    __tablename__ = 'user_cities'
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(64), nullable=False)
    client_ip = db.Column(db.String(64), nullable=False)
    latitude = db.Column(db.String(64), nullable=False)
    longitude = db.Column(db.String(64), nullable=False)
    clicked_city = db.Column(db.String(64), nullable=False)
    is_closest = db.Column(db.String(64), nullable=False)
    clicked_time = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"<LoginLog {self.userid} logged in from {self.ip_address} at {self.login_time}>"