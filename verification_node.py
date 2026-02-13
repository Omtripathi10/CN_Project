import socket
import cv2
import pickle
import struct
import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
import os

HOST = '0.0.0.0'
PORT = 9999
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes AES-256 key

previous_hash = b'0'
used_nonces = set()

def decrypt_data(data):
    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server listening...")

conn, addr = server_socket.accept()
print(f"Connected from {addr}")

while True:
    data_size = struct.calcsize("Q")
    packed_msg_size = conn.recv(data_size)
    if not packed_msg_size:
        break

    msg_size = struct.unpack("Q", packed_msg_size)[0]

    data = b""
    while len(data) < msg_size:
        data += conn.recv(4096)

    decrypted = decrypt_data(data)

    packet = pickle.loads(decrypted)

    frame_bytes = packet['frame']
    timestamp = packet['timestamp']
    nonce = packet['nonce']
    current_hash = packet['hash']
    prev_hash_client = packet['prev_hash']

    # Replay detection
    if nonce in used_nonces:
        print("⚠ Replay detected!")
        continue
    used_nonces.add(nonce)

    # Hash verification
    calculated_hash = hashlib.sha256(frame_bytes + previous_hash).digest()

    if calculated_hash != current_hash:
        print("⚠ Integrity violation!")
    else:
        print("✅ Frame verified")

    previous_hash = current_hash

    frame = cv2.imdecode(frame_bytes, cv2.IMREAD_COLOR)
    cv2.imshow("Secure Stream", frame)

    if cv2.waitKey(1) == ord('q'):
        break

conn.close()
cv2.destroyAllWindows()
