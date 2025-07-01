import json
import base64
from crypto_utils import CryptoUtils  # Import các hàm mã hóa/giải mã

# Hàm giải mã dữ liệu từ file JSON đầu vào và lưu ra file thật
def decrypt_file_from_json(json_path, output_path):
    # Mở và đọc nội dung JSON
    with open(json_path, 'r') as f:
        data = json.load(f)

    print(f"Session key: {data['session_key']}")  # In session_key (chuỗi base64)
    
    # Giải mã khóa AES từ base64
    session_key = base64.b64decode(data['session_key'])
    print(f"🔍 Session key length: {len(session_key)} bytes")  # Kiểm tra độ dài khóa

    # Giải mã iv và ciphertext từ base64
    iv = base64.b64decode(data['iv'])
    cipher = base64.b64decode(data['cipher'])

    # Kiểm tra hash để xác minh tính toàn vẹn
    expected_hash = data['hash']  # Hash từ JSON
    actual_hash = CryptoUtils.calculate_hash(iv, cipher)  # Tính lại hash thực tế
    if expected_hash != actual_hash:
        raise ValueError("File bị lỗi toàn vẹn! (hash mismatch)")

    # Giải mã dữ liệu gốc bằng AES-CBC
    decrypted_data = CryptoUtils.decrypt_aes_cbc(cipher, session_key, iv)

    # Ghi nội dung đã giải mã ra file
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f" ✅ Đã giải mã và lưu file tại: {output_path}")

# Nếu chạy file này trực tiếp thì thực thi đoạn dưới
if __name__ == '__main__':
    # Mở JSON và lấy tên file gốc 
    with open('downloaded_data.json', 'r') as f:
        data = json.load(f)
    output_filename = data.get('filename', 'decrypted_output.py')  
    decrypt_file_from_json('downloaded_data.json', output_filename) 
