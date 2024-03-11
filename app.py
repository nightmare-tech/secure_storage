# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ENCRYPTED_FOLDER'] = 'encrypted/'

# Set the encryption key (ideally, this should be fetched securely from a key management service)
encryption_key = b'0123456789abcdef0123456789abcdef'

# Create the upload and encrypted folders if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

# Function to encrypt a file
from cryptography.hazmat.primitives import padding

def encrypt_file(file_path, encrypted_path):
    # Read the file contents
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Create a cipher object for AES encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # Add padding to the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded file contents
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the encrypted file
    with open(encrypted_path, 'wb') as f:
        f.write(ciphertext)

# Function to decrypt a file
def decrypt_file(encrypted_path, decrypted_path):
    # Read the encrypted file contents
    with open(encrypted_path, 'rb') as f:
        ciphertext = f.read()

    # Create a cipher object for AES decryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the file contents
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted file
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

# Route for the home page
@app.route('/')
def home():
    encrypted_files = os.listdir(app.config['ENCRYPTED_FOLDER'])
    return render_template('index.html', encrypted_files=encrypted_files)

# Route for uploading a file
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename + '.encrypted')
        try:
            encrypt_file(upload_path, encrypted_path)
            
            # Remove the original file after encryption
            os.remove(upload_path)
        except Exception as e:
            # Handle any errors that occur during encryption or file deletion
            print("Error:", e)

        return redirect(url_for('home'))

# Route for downloading a file
@app.route('/download/<filename>')
def download_file(filename):
    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename[:-10])  # Remove '.encrypted' from the filename

    decrypt_file(encrypted_path, decrypted_path)

    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
