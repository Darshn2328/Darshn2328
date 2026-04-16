from flask import Flask, render_template, request, send_file
import os
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# 🔐 Generate key
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# 🔒 Encrypt
def encrypt_file(filepath, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)

    with open(filepath, "rb") as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    output_path = os.path.join(OUTPUT_FOLDER, os.path.basename(filepath) + ".enc")

    with open(output_path, "wb") as f:
        f.write(salt + iv + enc)

    return output_path

# 🔓 Decrypt
def decrypt_file(filepath, password):
    with open(filepath, "rb") as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    enc_data = data[32:]

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor().update(enc_data) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    final = unpadder.update(dec) + unpadder.finalize()

    output_path = os.path.join(OUTPUT_FOLDER, os.path.basename(filepath).replace(".enc", "_decrypted"))

    with open(output_path, "wb") as f:
        f.write(final)

    return output_path

# 🌐 Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/process", methods=["POST"])
def process():
    file = request.files["file"]
    password = request.form["password"]
    action = request.form["action"]

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    if action == "encrypt":
        output = encrypt_file(filepath, password)
    else:
        output = decrypt_file(filepath, password)

    return send_file(output, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)