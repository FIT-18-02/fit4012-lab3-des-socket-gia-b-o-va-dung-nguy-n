import struct
from typing import Tuple
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes # Dùng cái này cho đúng bài Lab

BLOCK_SIZE = 8
HEADER_SIZE = 8 + 8 + 4 # 20 byte

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Dữ liệu rỗng, không thể bỏ padding.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding không hợp lệ.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding PKCS#7 không hợp lệ.")
    return data[:-pad_len]

def encrypt_des_cbc(plain: bytes, key: bytes | None = None, iv: bytes | None = None) -> Tuple[bytes, bytes, bytes]:
    # Sinh khóa và IV ngẫu nhiên nếu không truyền vào
    key = key or get_random_bytes(8)
    iv = iv or get_random_bytes(8)
    if len(key) != 8 or len(iv) != 8:
        raise ValueError("DES key và IV phải dài đúng 8 byte.")
    des = DES.new(key, DES.MODE_CBC, iv)
    cipher_bytes = des.encrypt(pad(plain))
    return key, iv, cipher_bytes

def decrypt_des_cbc(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    if len(key) != 8 or len(iv) != 8:
        raise ValueError("DES key và IV phải dài đúng 8 byte.")
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext phải có độ dài là bội số của 8 byte.")
    des = DES.new(key, DES.MODE_CBC, iv)
    return unpad(des.decrypt(cipher_bytes))

def build_packet(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    # Đóng gói theo thứ tự: Key(8) + IV(8) + Length(4) + Ciphertext
    return key + iv + struct.pack('!I', len(cipher_bytes)) + cipher_bytes

def parse_header(header: bytes) -> tuple[bytes, bytes, int]:
    if len(header) != HEADER_SIZE:
        raise ValueError("Header phải dài đúng 20 byte.")
    key = header[:8]
    iv = header[8:16]
    length = struct.unpack('!I', header[16:20])[0]
    return key, iv, length

def recv_exact(conn, n: int) -> bytes:
    chunks = []
    received = 0
    while received < n:
        chunk = conn.recv(n - received)
        if not chunk:
            raise ConnectionError("Kết nối bị đóng bất ngờ.")
        chunks.append(chunk)
        received += len(chunk)
    return b''.join(chunks)