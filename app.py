from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
import datetime
from sympy import randprime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

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
    return [pow(ord(c), e, n) for c in message]

def decrypt(cipher, private_key):
    d, n = private_key
    # Decrypt numbers and convert back to text
    return ''.join([chr(pow(c, d, n)) for c in cipher])

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
def index():
    return render_template('main.html')

@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if login_user(email, password):
            session['email'] = email
            return redirect(url_for('home'))
        return render_template('login.html', error="Invalid email or password")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match")
        
        if len(password) < 6:
            return render_template('signup.html', error="Password must be at least 6 characters long")
        
        if save_user(email, password):
            session['email'] = email
            return redirect(url_for('home'))
        return render_template('signup.html', error="Email already exists")
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('index'))

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    if 'email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    bits = int(request.form.get('bits', 1024))
    public_key, private_key = generate_key_pair(bits)
    
    # Log the key generation with more details
    history_entry = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'operation': 'generate_keys',
        'key_size': bits,
        'public_key': str(public_key),
        'private_key': str(private_key)
    }
    save_history_for_user(session['email'], history_entry)
    
    return jsonify({
        'public_key': str(public_key),
        'private_key': str(private_key)
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    if 'email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    message = request.form.get('message')
    public_key = eval(request.form.get('public_key'))
    cipher = encrypt(message, public_key)
    
    # Log the operation with more details
    history_entry = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'operation': 'encrypt',
        'input': message,
        'public_key': str(public_key),
        'output': str(cipher)
    }
    save_history_for_user(session['email'], history_entry)
    
    return jsonify({'cipher': str(cipher)})

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    if 'email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    cipher = eval(request.form.get('cipher'))
    private_key = eval(request.form.get('private_key'))
    message = decrypt(cipher, private_key)
    
    # Log the operation with more details
    history_entry = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'operation': 'decrypt',
        'input': str(cipher),
        'private_key': str(private_key),
        'output': message
    }
    save_history_for_user(session['email'], history_entry)
    
    return jsonify({'message': message})

@app.route('/history')
def get_history():
    if 'email' not in session:
        return redirect(url_for('login'))
    history = load_history_for_user(session['email'])
    return render_template('history.html', history=history)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 