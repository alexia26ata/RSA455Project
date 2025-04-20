from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    operations = db.relationship('Operation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

def get_lebanon_time():
    lebanon_tz = pytz.timezone('Asia/Beirut')
    return datetime.now(lebanon_tz)

class Operation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation_type = db.Column(db.String(20), nullable=False)  # 'encrypt' or 'decrypt'
    input_data = db.Column(db.Text, nullable=False)
    output_data = db.Column(db.Text, nullable=False)
    key_size = db.Column(db.Integer, nullable=False)
    keys_used = db.Column(db.Text, nullable=False)  # JSON string of keys used
    timestamp = db.Column(db.DateTime(timezone=True), default=get_lebanon_time) 