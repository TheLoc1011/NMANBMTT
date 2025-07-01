from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from crypto_utils import CryptoUtils
import base64, json, os, socket, threading, time
from io import BytesIO
from Crypto.Random import get_random_bytes

app = Flask(__name__)
CORS(app)

stored_files = {}  # Lưu file mã hóa
last_encrypted_package = None  # Dữ liệu cuối cùng để gửi tới node

# Sinh khóa RSA và session key AES
private_key, public_key = CryptoUtils.generate_rsa_key_pair()   
session_key = get_random_bytes(32)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    global last_encrypted_package
    try:
        uploaded_file = request.files.get('file')
        if not uploaded_file:
            return "Không nhận được file", 400

        file_data = uploaded_file.read()
        iv = get_random_bytes(16)
        ciphertext = CryptoUtils.encrypt_aes_cbc(file_data, session_key, iv)
        file_hash = CryptoUtils.calculate_hash(iv, ciphertext)

        metadata = {
            'filename': uploaded_file.filename,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'file_size': len(file_data)
        }
        metadata_str = json.dumps(metadata)
        signature = CryptoUtils.sign_metadata(metadata_str, private_key)

        data_package = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'cipher': base64.b64encode(ciphertext).decode('utf-8'),
            'hash': file_hash,
            'sig': signature,
            'filename': uploaded_file.filename,
            'metadata': metadata_str
        }

        stored_files[metadata_str] = {
            'data': data_package,
            'session_key': base64.b64encode(session_key).decode('utf-8')
        }

        last_encrypted_package = {
            'iv': data_package['iv'],
            'cipher': data_package['cipher'],
            'hash': data_package['hash'],
            'sig': data_package['sig'],
            'session_key': stored_files[metadata_str]['session_key'],
            'filename': data_package['filename'],
            'metadata': metadata_str
        }

        return "Upload thành công!"
    except Exception as e:
        return f"Lỗi upload: {str(e)}", 500

@app.route('/send-to-cloud', methods=['POST'])
def send_to_cloud():
    if not last_encrypted_package:
        return "Chưa có dữ liệu để gửi", 400

    data_json = json.dumps(last_encrypted_package)

    result1 = send_to_node(('localhost', 9001), data_json)
    result2 = send_to_node(('localhost', 9002), data_json)
    return f"Node 1: {result1}\nNode 2: {result2}"

@app.route('/download-from-node', methods=['GET'])
def download_from_node():
    try:
        file_data = request_download(('localhost', 9001))
        return send_file(BytesIO(file_data), as_attachment=True, download_name='plan.txt')
    except Exception as e:
        return f"Lỗi khi tải từ node: {str(e)}", 500

# Hàm gửi dữ liệu JSON tới node qua socket
def send_to_node(address, data_json_str):
    try:
        s = socket.socket()
        s.connect(address)
        s.sendall(data_json_str.encode('utf-8'))
        response = s.recv(1024).decode()
        s.close()
        return response
    except Exception as e:
        return f"Lỗi gửi tới node {address}: {str(e)}"

# Hàm nhận file từ node

def request_download(address):
    s = socket.socket()
    s.connect(address)
    s.sendall(b'DOWNLOAD')
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data
@app.route('/download', methods=['GET'])
def download():
    try:
        if not stored_files:
            return jsonify({'error': 'Không có file nào'}), 404

        latest_entry = list(stored_files.values())[-1]
        data_with_key = latest_entry['data'].copy()
        data_with_key['session_key'] = latest_entry['session_key']
        return jsonify(data_with_key)
    except Exception as e:
        return jsonify({'error': f'Lỗi download: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)
