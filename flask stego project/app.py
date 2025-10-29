from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image
import os, struct
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import gzip

UPLOAD_FOLDER = "static/encoded"
SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITER = 200_000
NONCE_SIZE = 12
MAGIC = b"STEG0G"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.environ.get("FLASK_SECRET", "devsecret")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def derive_key(password: str, salt: bytes):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)

def aes_gcm_encrypt(plaintext: bytes, password: str):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return salt + nonce + tag + ct

def aes_gcm_decrypt(blob: bytes, password: str):
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    tag = blob[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
    ct = blob[SALT_SIZE+NONCE_SIZE+16:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def bytes_to_bits(b: bytes):
    for byte in b:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def bits_to_bytes(bits):
    b = bytearray()
    val = 0
    cnt = 0
    for bit in bits:
        val = (val << 1) | bit
        cnt += 1
        if cnt == 8:
            b.append(val)
            val = 0
            cnt = 0
    return bytes(b)

def embed_payload_in_image(img: Image.Image, payload: bytes, lsb=1):
    img = img.convert('RGBA')
    arr = list(img.getdata())
    w,h = img.size
    capacity = w*h*3*lsb
    header = MAGIC + struct.pack(">I", len(payload))
    full = header + payload
    if len(full)*8 > capacity:
        raise ValueError("Payload too large for chosen image.")
    bititer = bytes_to_bits(full)
    new_pixels = []
    for idx, px in enumerate(arr):
        r,g,b,a = px
        new_rgb = []
        for channel in (r,g,b):
            new_val = channel
            for bpos in range(lsb):
                try:
                    bit = next(bititer)
                except StopIteration:
                    new_rgb.append(new_val)
                    break
                new_val = (new_val & ~(1 << bpos)) | (bit << bpos)
            else:
                new_rgb.append(new_val)
                continue
            # stopped early due to StopIteration
            while len(new_rgb) < 3:
                new_rgb.append((r,g,b)[len(new_rgb)])
            new_pixels.append((new_rgb[0], new_rgb[1], new_rgb[2], a))
            new_pixels.extend([(p[0],p[1],p[2],p[3]) for p in arr[len(new_pixels):]])
            new_img = Image.new('RGBA', (w,h))
            new_img.putdata(new_pixels)
            return new_img
        new_pixels.append((new_rgb[0], new_rgb[1], new_rgb[2], a))
    new_img = Image.new('RGBA', (w,h))
    new_img.putdata(new_pixels)
    return new_img

def extract_payload_from_image(img: Image.Image, lsb=1):
    img = img.convert('RGBA')
    arr = list(img.getdata())
    bits = []
    for px in arr:
        for channel in px[:3]:
            for bpos in range(lsb):
                bits.append((channel >> bpos) & 1)
    data = bits_to_bytes(bits)
    if len(data) < len(MAGIC)+4:
        raise ValueError("No stego header found.")
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("MAGIC mismatch - not a valid stego image.")
    payload_len = struct.unpack(">I", data[len(MAGIC):len(MAGIC)+4])[0]
    start = len(MAGIC)+4
    end = start + payload_len
    if len(data) < end:
        raise ValueError("Incomplete payload in image.")
    return data[start:end]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['GET','POST'])
def encode():
    if request.method == 'POST':
        pw = request.form.get('password','').strip()
        lsb = int(request.form.get('lsb','1'))
        file = request.files.get('cover')
        secret_file = request.files.get('secret')
        secret_text = request.form.get('secret_text','').encode('utf-8') if request.form.get('secret_text') else None
        if not file or not pw:
            flash("Provide cover PNG and a password.", "error")
            return redirect(url_for('encode'))
        filename = secure_filename(file.filename)
        if not filename.lower().endswith('.png'):
            flash("Only PNG cover images allowed.", "error")
            return redirect(url_for('encode'))
        cover = Image.open(file.stream)
        if secret_file and secret_file.filename != '':
            payload = secret_file.read()
        elif secret_text:
            payload = secret_text
        else:
            flash("Provide text or file to hide.", "error")
            return redirect(url_for('encode'))
        payload = gzip.compress(payload)
        enc = aes_gcm_encrypt(payload, pw)
        try:
            stego_img = embed_payload_in_image(cover, enc, lsb=lsb)
        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for('encode'))
        out_buf = BytesIO()
        stego_img.save(out_buf, format='PNG')
        out_buf.seek(0)
        out_name = secure_filename("stego_"+filename)
        out_path = os.path.join(app.config['UPLOAD_FOLDER'], out_name)
        with open(out_path, 'wb') as f:
            f.write(out_buf.read())
        return send_file(out_path, as_attachment=True)
    return render_template('encode.html')

@app.route('/decode', methods=['GET','POST'])
def decode():
    if request.method == 'POST':
        pw = request.form.get('password','').strip()
        lsb = int(request.form.get('lsb','1'))
        file = request.files.get('stego')
        if not file or not pw:
            flash("Provide stego PNG and password.", "error")
            return redirect(url_for('decode'))
        img = Image.open(file.stream)
        try:
            enc = extract_payload_from_image(img, lsb=lsb)
            dec = aes_gcm_decrypt(enc, pw)
            dec = gzip.decompress(dec)
        except Exception as e:
            flash("Failed to decode: " + str(e), "error")
            return redirect(url_for('decode'))
        return send_file(BytesIO(dec), as_attachment=True, download_name='extracted.bin')
    return render_template('decode.html')

if __name__ == '__main__':
    app.run(debug=True)
