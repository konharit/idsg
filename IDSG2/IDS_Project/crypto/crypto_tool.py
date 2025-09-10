from flask import Blueprint, render_template, request, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

crypto_bp = Blueprint('crypto', __name__)

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def aes_encrypt(plain_text, key):
    key = key.ljust(16)[:16].encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text).encode())
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt(iv, ct, key):
    key = key.ljust(16)[:16].encode()
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct).decode('utf-8'))
    return pt

@crypto_bp.route('/crypto', methods=['GET', 'POST'])
def crypto_home():
    result = None
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text')
        key = request.form.get('key')
        if not text or not key:
            error = 'Text and key are required.'
        else:
            try:
                if action == 'encrypt':
                    iv, ct = aes_encrypt(text, key)
                    result = f"IV: {iv}\nCiphertext: {ct}"
                elif action == 'decrypt':
                    iv = request.form.get('iv')
                    ct = request.form.get('ciphertext')
                    if not iv or not ct:
                        error = 'IV and ciphertext are required for decryption.'
                    else:
                        pt = aes_decrypt(iv, ct, key)
                        result = f"Plaintext: {pt}"
            except Exception as e:
                error = f"Error: {str(e)}"
    return render_template('crypto.html', result=result, error=error)
