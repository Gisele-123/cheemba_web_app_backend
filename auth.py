from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail, Message
import datetime
import random
import jwt
import os
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

auth = Flask(__name__)
CORS(auth, origins="https://cheemba-web-app.vercel.app/login", supports_credentials=True)

auth.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:yezu@localhost:5432/cheemba'
auth.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
auth.config['SECRET_KEY'] = 'my_secret_key'

db = SQLAlchemy(auth)
bcrypt = Bcrypt(auth)

auth.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

auth.config['MAIL_SERVER'] = 'smtp.gmail.com'
auth.config['MAIL_PORT'] = 587
auth.config['MAIL_USE_TLS'] = True
auth.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') 
auth.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') 
auth.config['MAIL_DEFAULT_SENDER'] = ('Cheemba', auth.config['MAIL_USERNAME'])  # Default sender

mail = Mail(auth)

class Company(db.Model):
    __tablename__ = 'company_table'
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(80), nullable=False)
    company_email = db.Column(db.String(80), unique=True, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(6), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

with auth.app_context():
    db.create_all()

@auth.route('/signup', methods=['POST'])
def signup():
    data = request.json
    company_name = data.get('company_name')
    company_email = data.get('company_email')
    location = data.get('location')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not all([company_name, company_email, location, password, confirm_password]):
        return jsonify({'message': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    if Company.query.filter_by(company_email=company_email).first():
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_company = Company(
        company_name=company_name,
        company_email=company_email,
        location=location,
        password=hashed_password
    )
    db.session.add(new_company)
    db.session.commit()

    return jsonify({'message': 'Company created successfully. Please verify your email.'}), 201

@auth.route('/email-verify', methods=['POST'])
def email_verify():
    if not request.is_json:
        return jsonify({"message": "Invalid data format. JSON expected."}), 400

    data = request.get_json()
    company_email = data.get('company_email')

    if not company_email:
        return jsonify({'message': 'Company email is required'}), 400

    verification_code = str(random.randint(100000, 999999))

    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="background-color: #f4f7fc; padding: 20px; border-radius: 10px; text-align: center;">
                <h2 style="color: #4CAF50;">Your Verification Code</h2>
                <p style="font-size: 16px;">Thank you for signing up with us! To complete your registration, use the verification code below:</p>
                <h3 style="font-size: 30px; color: #333; font-weight: bold;">{verification_code}</h3>
                <p style="font-size: 14px; color: #888;">This code will expire in 15 minutes. Please use it before it expires.</p>
                <div style="margin-top: 20px; padding: 10px; background-color: #4CAF50; color: white; border-radius: 5px; width: 200px; text-align: center; margin-left: auto; margin-right: auto;">
                    <p style="font-size: 16px;">If you didn't request this, you can ignore this message.</p>
                </div>
            </div>
        </body>
    </html>
    """

    try:
        # Create message
        msg = Message(
            subject="Cheemba Verification Code",
            recipients=[company_email]
        )
        # Attach HTML content
        msg.html = html_content

        # Send email
        mail.send(msg)

        # Save verification code and expiration time in the database
        company = Company.query.filter_by(company_email=company_email).first()
        if company:
            company.verification_code = verification_code
            company.expires_at = datetime.datetime.now() + datetime.timedelta(minutes=15)
            db.session.commit()

        return jsonify({'message': 'Verification code sent to your email.'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send email', 'error': str(e)}), 500

@auth.route('/confirm-verify', methods=['POST'])
def confirm_verify():
    data = request.json
    company_email = data.get('company_email')
    verification_code = data.get('verification_code')

    if not company_email or not verification_code:
        return jsonify({'message': 'Company email and verification code are required'}), 400

    company = Company.query.filter_by(company_email=company_email).first()
    if not company:
        return jsonify({'message': 'Company not found'}), 404

    if company.is_verified:
        return jsonify({'message': 'Email already verified'}), 400

    if company.verification_code != verification_code:
        return jsonify({'message': 'Invalid verification code'}), 400

    if datetime.datetime.now() > company.expires_at:
        return jsonify({'message': 'Verification code has expired'}), 400

    company.is_verified = True
    company.verification_code = None 
    company.expires_at = None
    db.session.commit()

    return jsonify({'message': 'Email successfully verified'}), 200

@auth.route('/login', methods=['POST'])
def login():
    data = request.json
    company_email = data.get('company_email')
    password = data.get('password')

    if not company_email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    company = Company.query.filter_by(company_email=company_email).first()

    if not company or not bcrypt.check_password_hash(company.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    if not company.is_verified:
        return jsonify({'message': 'Email not verified'}), 400

    token = jwt.encode({
        'company_id': company.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, auth.config['JWT_SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'company_name': company.company_name,
        'token': token
    }), 200

@auth.route('/logout', methods=['POST'])
def logout():
    session.pop('company_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]

            data = jwt.decode(token, auth.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_company = Company.query.get(data['company_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_company, *args, **kwargs)

    return decorated

if __name__ == '__main__':
    with auth.app_context():
        db.drop_all()
        db.create_all()
    auth.run(debug=True, host='0.0.0.0', port=5000)