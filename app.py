import os
import time
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, session, abort
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ENCRYPTED_FOLDER'] = 'encrypted/'
app.config['DATABASE'] = 'database.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiter variables
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # Block for 5 minutes

# Function to fetch the encryption key securely from an environment variable
def get_encryption_key():
    key = os.getenv('ENCRYPTION_KEY')
    if key is None:
        print("Warning: Using default encryption key. This is insecure for production use.")
        return b'0123456789abcdef0123456789abcdef'
    return key.encode()

# Retrieve the encryption key
encryption_key = get_encryption_key()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

# Initialize database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                        )''')
        conn.commit()

# Initialize database when the app starts
init_db()

# Rate limiter function
def is_blocked(ip):
    attempt = LOGIN_ATTEMPTS.get(ip)
    if attempt:
        if attempt['count'] >= MAX_ATTEMPTS and time.time() - attempt['first_attempt'] < BLOCK_TIME:
            return True
        elif time.time() - attempt['first_attempt'] > BLOCK_TIME:
            # Reset attempts after block time expires
            LOGIN_ATTEMPTS[ip] = {'count': 0, 'first_attempt': time.time()}
    return False

def record_login_attempt(ip):
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = {'count': 1, 'first_attempt': time.time()}
    else:
        LOGIN_ATTEMPTS[ip]['count'] += 1

# Function to decrypt a file
def decrypt_file(encrypted_path, decrypted_path):
    with open(encrypted_path, 'rb') as f:
        ciphertext = f.read()

    backend = default_backend()
    iv = ciphertext[:16]  # Extract the first 16 bytes as the IV
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    except Exception as e:
        print("Error during unpadding:", e)
        return

    with open(decrypted_path, 'wb') as f:
        f.write(unpadded_plaintext)

# Function to encrypt a file
def encrypt_file(file_path, encrypted_path):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = iv + encryptor.update(padded_plaintext) + encryptor.finalize()

    with open(encrypted_path, 'wb') as f:
        f.write(ciphertext)

def is_logged_in():
    return 'username' in session

@app.before_request
def limit_login_attempts():
    if request.endpoint == 'login' and request.method == 'POST':
        ip = request.remote_addr
        if is_blocked(ip):
            abort(429, description="Too many login attempts. Try again later.")

@app.route('/')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))

    encrypted_files = os.listdir(app.config['ENCRYPTED_FOLDER'])
    return render_template('index.html', encrypted_files=encrypted_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(app.config['DATABASE']) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username=?', (username,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode(), user[2].encode()):
                session['username'] = username
                return redirect(url_for('home'))
            else:
                record_login_attempt(ip)
                return render_template('login.html', error='Invalid username or password')

    return render_template('login.html', error=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        with sqlite3.connect(app.config['DATABASE']) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if not is_logged_in():
        return redirect(url_for('login'))

    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename + '.encrypted')
        encrypt_file(upload_path, encrypted_path)

        os.remove(upload_path)

    return redirect(url_for('home'))

@app.route('/download/<filename>')
def download_file(filename):
    if not is_logged_in():
        return redirect(url_for('login'))

    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename[:-10])

    decrypt_file(encrypted_path, decrypted_path)
    response = send_file(decrypted_path, as_attachment=True)

    os.remove(decrypted_path)

    return response

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

