from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import json
import os
from datetime import datetime
import pytz
from sympy import randprime
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Operation
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Add json filter
@app.template_filter('from_json')
def from_json(value):
    return json.loads(value)

# Initialize the database
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

# Set Lebanon timezone
lebanon_tz = pytz.timezone('Asia/Beirut')

def get_lebanon_time():
    return datetime.now(lebanon_tz)

# Ensure the history directory exists
if not os.path.exists('history'):
    os.makedirs('history')

# Initialize users.json if it doesn't exist
if not os.path.exists('users.json'):
    with open('users.json', 'w') as f:
        json.dump({}, f)

def get_user_history_file(email):
    # Create a history directory if it doesn't exist
    if not os.path.exists("history"):
        os.makedirs("history")
    return os.path.join("history", f"{email.replace('@', '_at_')}.json")

def save_history_for_user(email, entry):
    history_file = get_user_history_file(email)
    if not os.path.exists(history_file):
        with open(history_file, "w") as f:
            json.dump([], f)
    
    with open(history_file, "r+") as f:
        history = json.load(f)
        history.append(entry)
        f.seek(0)
        json.dump(history, f, indent=4)
        f.truncate()

def load_history_for_user(email):
    history_file = get_user_history_file(email)
    if not os.path.exists(history_file):
        return []
    with open(history_file, "r") as f:
        return json.load(f)

def generate_key_pair(bits=1024):
    # Generate two random prime numbers
    p = randprime(2**(bits//2-1), 2**(bits//2))
    q = randprime(2**(bits//2-1), 2**(bits//2))
    
    n = p * q
    phi = (p-1) * (q-1)
    
    # Choose public exponent e
    e = 65537
    
    # Calculate private exponent d
    d = pow(e, -1, phi)
    
    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    # Convert message to numbers and encrypt
    try:
        return [pow(ord(c), e, n) for c in message]
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def decrypt(cipher, private_key):
    d, n = private_key
    # Decrypt numbers and convert back to text
    try:
        # Convert string representation of list to actual list if needed
        if isinstance(cipher, str):
            cipher = eval(cipher)
        # Decrypt each number and convert back to character
        decrypted = []
        for c in cipher:
            try:
                m = pow(c, d, n)
                if 0 <= m <= 0x10FFFF:  # Valid Unicode range
                    decrypted.append(chr(m))
                else:
                    raise ValueError(f"Invalid character code: {m}")
            except Exception as e:
                raise ValueError(f"Failed to decrypt character: {str(e)}")
        return ''.join(decrypted)
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def save_user(email, password):
    with open('users.json', 'r+') as f:
        users = json.load(f)
        if email in users:
            return False
        users[email] = generate_password_hash(password)
        f.seek(0)
        json.dump(users, f)
        f.truncate()
    return True

def login_user(email, password):
    with open('users.json', 'r') as f:
        users = json.load(f)
        if email not in users:
            return False
        return check_password_hash(users[email], password)

@app.route('/')
def main():
    session.clear()
    return render_template('main.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        
        flash('Invalid email or password. Please check your credentials and try again.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('This email is already registered. Please use a different email or login.', 'error')
            return render_template('signup.html')
        
        # Create new user
        try:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'error')
            return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('main'))

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    bits = int(request.form.get('bits', 1024))
    public_key, private_key = generate_key_pair(bits)
    
    try:
        # Log the operation in the database with Lebanon time
        operation = Operation(
            user_id=session['user_id'],
            operation_type='generate_keys',
            input_data='',
            output_data=json.dumps({'public_key': str(public_key), 'private_key': str(private_key)}),
            key_size=bits,
            keys_used=json.dumps({'public_key': str(public_key), 'private_key': str(private_key)}),
            timestamp=get_lebanon_time()
        )
        db.session.add(operation)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error saving operation: {str(e)}")
    
    return jsonify({
        'public_key': str(public_key),
        'private_key': str(private_key)
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    message = request.form.get('message')
    try:
        public_key = eval(request.form.get('public_key'))
        cipher = encrypt(message, public_key)
        if cipher is None:
            return jsonify({'error': 'Encryption failed'}), 400
        
        # Log the operation in the database with Lebanon time
        operation = Operation(
            user_id=session['user_id'],
            operation_type='encrypt',
            input_data=message,
            output_data=str(cipher),
            key_size=len(str(public_key[1])),
            keys_used=json.dumps({'public_key': str(public_key)}),
            timestamp=get_lebanon_time()
        )
        db.session.add(operation)
        db.session.commit()
        
        return jsonify({'cipher': str(cipher)})
    except Exception as e:
        db.session.rollback()
        print(f"Error in encryption: {str(e)}")
        return jsonify({'error': 'Invalid public key or message'}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    try:
        cipher = request.form.get('cipher')
        private_key = eval(request.form.get('private_key'))
        decrypted = decrypt(cipher, private_key)
        
        if decrypted is None:
            return jsonify({'error': 'Decryption failed. Please check your private key and ciphertext.'}), 400
        
        # Log the operation in the database with Lebanon time
        operation = Operation(
            user_id=session['user_id'],
            operation_type='decrypt',
            input_data=str(cipher),
            output_data=decrypted,
            key_size=len(str(private_key[1])),
            keys_used=json.dumps({'private_key': str(private_key)}),
            timestamp=get_lebanon_time()
        )
        db.session.add(operation)
        db.session.commit()
        
        return jsonify({'message': decrypted})
    except Exception as e:
        db.session.rollback()
        print(f"Error in decryption: {str(e)}")
        return jsonify({'error': 'Invalid private key or ciphertext'}), 400

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        operations = Operation.query.filter_by(user_id=session['user_id']).order_by(Operation.timestamp.desc()).all()
        return render_template('history.html', operations=operations)
    except Exception as e:
        print(f"Error retrieving history: {str(e)}")
        flash('Error retrieving history', 'error')
        return redirect(url_for('main'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 