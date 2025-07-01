import socket
import json
import base64
import os
from crypto_utils import CryptoUtils
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

HOST = 'localhost'
PORT = 9001
STORAGE_PATH = 'plan_node1.txt'
PRIVATE_KEY = None

# Tạo khóa riêng giả lập nếu cần
if not os.path.exists('private_key_node1.pem'):
    private_key, public_key = CryptoUtils.generate_rsa_key_pair()
    with open('private_key_node1.pem', 'wb') as f:
        f.write(private_key)
    with open('public_key_node1.pem', 'wb') as f:
        f.write(public_key)

with open('private_key_node1.pem', 'rb') as f:
    PRIVATE_KEY = f.read()

# Mở socket TCP server
s = socket.socket()
s.bind((HOST, PORT))
s.listen(5)
print(f"📡 Node 1 đang lắng nghe tại {HOST}:{PORT}...")

while True:
    conn, addr = s.accept()
    print(f"📥 Kết nối từ {addr}")
    data = b""
    while True:
        part = conn.recv(4096)
        if not part:
            break
        data += part

    # Nếu chỉ là yêu cầu DOWNLOAD
    if data == b'DOWNLOAD':
        if os.path.exists(STORAGE_PATH):
            with open(STORAGE_PATH, 'rb') as f:
                conn.sendall(f.read())
            print("📤 Đã gửi file mã hóa về client.")
        else:
            conn.sendall(b'')
        conn.close()
        continue

    try:
        received = json.loads(data.decode())
        iv = base64.b64decode(received['iv'])
        cipher = base64.b64decode(received['cipher'])
        session_key = base64.b64decode(received['session_key'])
        expected_hash = received['hash']
        sig = received['sig']
        metadata = received['metadata']

        # Kiểm tra hash
        actual_hash = CryptoUtils.calculate_hash(iv, cipher)
        if actual_hash != expected_hash:
            conn.sendall(b'NACK: integrity error')
            print("❌ Lỗi toàn vẹn dữ liệu")
            conn.close()
            continue

        # Kiểm tra chữ ký
        with open('public_key_node1.pem', 'rb') as f:
            pub = f.read()
        if not CryptoUtils.verify_signature(metadata, sig, pub):
            conn.sendall(b'NACK: signature error')
            print("❌ Lỗi xác thực chữ ký")
            conn.close()
            continue

        # Giải mã
        plaintext = CryptoUtils.decrypt_aes_cbc(cipher, session_key, iv)
        with open(STORAGE_PATH, 'wb') as f:
            f.write(plaintext)

        conn.sendall(b'ACK')
        print("✅ File đã được lưu tại node 1")
    except Exception as e:
        conn.sendall(f'NACK: {str(e)}'.encode())
        print(f"❌ Lỗi xử lý: {e}")

    conn.close()
