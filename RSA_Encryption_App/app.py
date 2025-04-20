from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
import datetime
import random
from sympy import randprime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# ====== RSA Utility Functions ======
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x, y = x2 - temp1 * x1, d - temp1 * y1
        x2, x1, d, y1 = x1, x, y1, y
    if temp_phi == 1:
        return d + phi

def generate_key_pair(bits):
    p = randprime(2**(bits//2-1), 2**(bits//2))
    q = randprime(2**(bits//2-1), 2**(bits//2))
    while p == q:
        q = randprime(2**(bits//2-1), 2**(bits//2))
    n = p * q
    phi = (p-1)*(q-1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(msg, key):
    e, n = key
    return [pow(ord(char), e, n) for char in msg]

def decrypt(cipher, key):
    d, n = key
    return ''.join([chr(pow(c, d, n)) for c in cipher])

def save_history(entry):
    if not os.path.exists("history.json"):
        with open("history.json", "w") as f:
            json.dump([], f)
    with open("history.json", "r+") as f:
        history = json.load(f)
        history.append(entry)
        f.seek(0)
        json.dump(history, f, indent=4)
        f.truncate()

def load_history():
    if not os.path.exists("history.json"):
        return []
    with open("history.json", "r") as f:
        return json.load(f)

# ====== Authentication Helper Functions ======
def signup_user(email, password):
    if not os.path.exists("users.json"):
        with open("users.json", "w") as f:
            json.dump([], f)
    with open("users.json", "r+") as f:
        users = json.load(f)
        for user in users:
            if user["email"] == email:
                return False
        users.append({
            "email": email,
            "password": generate_password_hash(password)
        })
        f.seek(0)
        json.dump(users, f, indent=4)
        f.truncate()
    return True

def login_user(email, password):
    if not os.path.exists("users.json"):
        return False
    with open("users.json", "r") as f:
        users = json.load(f)
        for user in users:
            if user["email"] == email and check_password_hash(user["password"], password):
                return True
    return False

# ====== Routes ======
@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if login_user(email, password):
        session['email'] = email
        return redirect(url_for('home'))
    return render_template('login.html', error="Invalid email or password")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if "@" not in email:
            return render_template('signup.html', error="Invalid email. Please include '@' in your email address.")
        if len(password) < 6:
            return render_template('signup.html', error="Password must be at least 6 characters.")
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match.")
        
        if signup_user(email, password):
            session['email'] = email
            return redirect(url_for('home'))
        return render_template('signup.html', error="User already exists.")
    
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for('index'))
    return render_template('home.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    bits = int(request.form.get('bits', 1024))
    public_key, private_key = generate_key_pair(bits)
    return jsonify({
        'public_key': str(public_key),
        'private_key': str(private_key)
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form.get('message')
    public_key = eval(request.form.get('public_key'))
    cipher = encrypt(message, public_key)
    save_history({
        'type': 'encrypt',
        'message': message,
        'cipher': str(cipher),
        'timestamp': datetime.datetime.now().isoformat()
    })
    return jsonify({'cipher': str(cipher)})

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    cipher = eval(request.form.get('cipher'))
    private_key = eval(request.form.get('private_key'))
    message = decrypt(cipher, private_key)
    save_history({
        'type': 'decrypt',
        'cipher': str(cipher),
        'message': message,
        'timestamp': datetime.datetime.now().isoformat()
    })
    return jsonify({'message': message})

@app.route('/history')
def get_history():
    if 'email' not in session:
        return redirect(url_for('index'))
    history = load_history()
    return render_template('history.html', history=history)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 