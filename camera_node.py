import socket
import cv2
import pickle
import struct
import hashlib
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

SERVER_IP = '10.70.101.194'
PORT = 9999
KEY = b'0123456789abcdef0123456789abcdef'

previous_hash = b'0'

def encrypt_data(data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

# Use webcam (0) OR phone URL
cap = cv2.VideoCapture(0)
# For phone:
# cap = cv2.VideoCapture("http://192.168.1.5:8080/video")

while True:
    ret, frame = cap.read()
    if not ret:
        break

    _, buffer = cv2.imencode('.jpg', frame)
    frame_bytes = buffer.tobytes()

    timestamp = time.time()
    nonce = os.urandom(12)

    current_hash = hashlib.sha256(frame_bytes + previous_hash).digest()

    packet = {
        'frame': frame_bytes,
        'timestamp': timestamp,
        'nonce': nonce,
        'hash': current_hash,
        'prev_hash': previous_hash
    }

    serialized = pickle.dumps(packet)
    encrypted = encrypt_data(serialized)

    message = struct.pack("Q", len(encrypted)) + encrypted
    client_socket.sendall(message)

    previous_hash = current_hash

cap.release()
client_socket.close()
