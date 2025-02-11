import clicksend_client
from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import datetime
import random
import jwt
import re
from clicksend_client import SmsMessage, SMSApi
from clicksend_client.rest import ApiException
import os
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

auth = Flask(__name__)
CORS(auth)

auth.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:yezu@localhost:5432/cheemba'
auth.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
auth.config['SECRET_KEY'] = 'my_secret_key'

db = SQLAlchemy(auth)
bcrypt = Bcrypt(auth)

# ClickSend API Configuration
CLICKSEND_USERNAME = os.getenv('CLICK_SEND_USERNAME')
CLICKSEND_API_KEY = os.getenv('CLICK_SEND_SMS_API_KEY')
configuration = clicksend_client.Configuration()
configuration.username = CLICKSEND_USERNAME
configuration.password = CLICKSEND_API_KEY

# Jwt key generation
#  Keys in .env and .env hidden in gitignore
auth.config['JWT_SECRET_KEY']=os.getenv('JWT_SECRET_KEY')

sms_api = SMSApi(clicksend_client.ApiClient(configuration))

class User(db.Model):
    __tablename__ = 'user_table'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    location = db.Column(db.String(200), unique=True, nullable=False)
    ch_code = db.Column(db.String(250), unique=True, nullable=False)
    marital_status = db.Column(db.String(30), unique=False, nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    is_phone_verified = db.Column(db.Boolean, default=False, nullable=False)

class PhoneVerification(db.Model):
    __tablename__ = "phone_verification"
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(15), nullable=False)
    verification_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)

class Notifications(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_table.id'), nullable=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

with auth.app_context():
    # db.drop_all()
    db.create_all()

@auth.route('/verify-phone', methods=['POST'])
def verify_phone():
    data = request.json
    phone_number = data.get('phone_number')

    if not phone_number:
        return jsonify({'message': 'Phone number is required'}), 400

    if not re.match(r'^0\d{9}$', phone_number):
        return jsonify({"error": "Invalid phone number format. It should start with 0 and be 10 digits long."}), 400

    if User.query.filter_by(phone_number=phone_number).first():
        return jsonify({"error": "Phone number already registered"}), 400

    verified_phone = PhoneVerification.query.filter_by(phone_number=phone_number, is_verified=True).first()
    if verified_phone:
        return jsonify({"error": "Phone number already verified"}), 400

    verification_code = str(random.randint(100000, 999999))
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=500)

    phone_verification = PhoneVerification(
        phone_number=phone_number,
        verification_code=verification_code,
        expires_at=expires_at
    )

    try:
        db.session.add(phone_verification)
        db.session.commit()

        # Send SMS via ClickSend
        sms_message = SmsMessage(
            source="python",
            body=f"Hi, your Cheemba verification code is: {verification_code}. It will expire in 10 minutes.",
            to=phone_number
        )
        sms_messages = clicksend_client.SmsMessageCollection(messages=[sms_message])

        try:
            api_response = sms_api.sms_send_post(sms_messages)
            print(f"SMS sent successfully: {api_response}")
        except ApiException as e:
            print(f"Exception when calling SmsApi->sms_send_post: {e}")
            return jsonify({"error": "Failed to send verification code"}), 500

        return jsonify({"success": "Verification code sent", "phone_number": phone_number}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@auth.route('/confirm-verification', methods=['POST'])
def confirm_verification():
    data = request.json
    phone_number = data.get('phone_number')
    verification_code = data.get('verification_code')

    if not phone_number or not verification_code:
        return jsonify({'message': 'Phone number and verification code are required'}), 400

    verification = PhoneVerification.query.filter_by(
        phone_number=phone_number,
        verification_code=verification_code
    ).first()

    if not verification:
        return jsonify({"error": "Invalid verification code"}), 400

    expires_at_aware = verification.expires_at.replace(tzinfo=datetime.timezone.utc)
    now_aware = datetime.datetime.now(datetime.timezone.utc)

    if now_aware > expires_at_aware:
        return jsonify({"error": "Verification code has expired"}), 400

    verification.is_verified = True
    db.session.commit()

    return jsonify({"success": "Phone number verified"}), 200

@auth.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    marital_status = data.get('marital_status')
    location = data.get('location')
    password = data.get('password')
    ch_code = data.get('ch_code')
    phone_number = data.get('phone_number')

    if not all([name, email, marital_status, location, password, ch_code, phone_number]):
        return jsonify({'message': 'All fields are required'}), 400

    verification = PhoneVerification.query.filter_by(
        phone_number=phone_number,
        is_verified=True
    ).first()

    if not verification:
        return jsonify({"error": "Phone number is not verified"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    if User.query.filter_by(phone_number=phone_number).first():
        return jsonify({'message': 'Phone number already registered'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(
        name=name,
        email=email,
        marital_status=marital_status,
        location=location,
        password=hashed_password,
        ch_code=ch_code,
        phone_number=phone_number,
        is_phone_verified=True
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@auth.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    ch_code = data.get('ch_code')

    if not email or not password or not ch_code:
        return jsonify({'message': 'Email, password, and Cheemba code are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  
    }, auth.config['JWT_SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'username': user.name,
        'token': token 
    }), 200

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            # Remove 'Bearer ' from the token string
            if token.startswith('Bearer '):
                token = token.split(' ')[1]

            # Decode the token
            data = jwt.decode(token, auth.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@auth.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200


@auth.route('/notifications/<int:user_id>', methods=['GET'])
def get_notifications(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    notifications = Notifications.query.filter_by(user_id=user_id).all()
    notification_list = [
        {
            "id": notification.id,
            "message": notification.message,
            "created_at": notification.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for notification in notifications
    ]   
    return jsonify({"notifications": notification_list}), 200

@auth.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'name': current_user.name,
        'email': current_user.email,
        'ch_code': current_user.ch_code,
        'marital_status': current_user.marital_status,
        'phone_number': current_user.phone_number,
        'location': current_user.location
    }), 200

if __name__ == '__main__':
    auth.run(debug=True, host='0.0.0.0', port=5000)