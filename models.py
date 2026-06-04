from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    # Comma-separated device IDs the user is allowed to configure (e.g. "1,2,3")
    allowed_devices = db.Column(db.String(256), default='')

    def get_allowed_device_ids(self):
        if not self.allowed_devices:
            return []
        try:
            return [int(x) for x in self.allowed_devices.split(',') if x.strip()]
        except Exception:
            return []

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, default=22, nullable=False)
    device_type = db.Column(db.String(50), default='cisco_ios')
    status = db.Column(db.String(20), default='Unknown')  # Online, Offline, Unknown
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Device {self.hostname} ({self.ip_address})>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20), default='INFO')  # INFO, WARNING, ERROR
    action = db.Column(db.String(200), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<Log {self.action} @ {self.timestamp}>'
