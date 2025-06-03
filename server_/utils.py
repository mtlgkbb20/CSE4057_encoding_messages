# server/utils.py
import os
import socket
import json
import logging
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from utils.crypto import (
    load_private_key_from_pem,
    load_public_cert_from_pem,
    verify_cert,
    derive_shared_secret,
    kdf_expand_shared_secret,
    aes_encrypt,
    aes_decrypt,
    compute_hmac,
    verify_hmac,
)
import base64
# server/utils.py içinde de:
import os   

# ----------------------------
# Logging Ayarları
# ----------------------------
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Handshake için log
hs_logger = logging.getLogger("server_handshake")
hs_logger.setLevel(logging.DEBUG)
hs_handler = logging.FileHandler(os.path.join(LOG_DIR, "handshake.log"))
hs_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
hs_logger.addHandler(hs_handler)

# Mesajlar için log
msg_logger = logging.getLogger("server_messages")
msg_logger.setLevel(logging.DEBUG)
msg_handler = logging.FileHandler(os.path.join(LOG_DIR, "messages.log"))
msg_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
msg_logger.addHandler(msg_handler)


# ----------------------------
# 1) Anahtar & Sertifika Yükleme
# ----------------------------
SERVER_KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(SERVER_KEYS_DIR, exist_ok=True)
SERVER_PRIVATE_KEY_PATH = os.path.join(SERVER_KEYS_DIR, "server_private_key.pem")
SERVER_PUBLIC_CERT_PATH = os.path.join(SERVER_KEYS_DIR, "server_public_cert.pem")

CA_PUBLIC_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "ca", "keys", "ca_public_cert.pem")


def load_server_credentials():
    """
    Sunucunun özel anahtarını ve sertifikasını (CA imzalı) yükler.
    """
    server_priv = load_private_key_from_pem(SERVER_PRIVATE_KEY_PATH)
    server_cert = load_public_cert_from_pem(SERVER_PUBLIC_CERT_PATH)
    ca_cert = load_public_cert_from_pem(CA_PUBLIC_CERT_PATH)
    return server_priv, server_cert, ca_cert


# ----------------------------
# 2) El Sıkışma (Handshake) Protokolü
# ----------------------------
def server_handshake(conn):
    """
    client ile handshake yapar:
    1) Client'tan Hello (JSON) bekle: {"cert": base64, "ecdh_pub": base64, "nonce": base64}
    2) Sertifikayı CA ile doğrula. Eğer geçerliyse:
    3) Server kendi sertifikasını ve ECDH public key'ini, rastgele nonce ile döner.
    4) Client'tan karşı nonce'lu ikinci adımı al (isteğe bağlı).
    5) ECDH raw secret -> HKDF ile enc_key, mac_key elde et.
    6) İlerideki metin alışverişi için bu anahtarları return et.
    """
    server_priv, server_cert, ca_cert = load_server_credentials()

    # 1) Client Hello: JSON formatta
    data = conn.recv(8192)
    client_hello = json.loads(data.decode())
    client_cert_bytes = base64.b64decode(client_hello["cert"])
    client_ecdh_pub_bytes = base64.b64decode(client_hello["ecdh_pub"])
    client_nonce = base64.b64decode(client_hello["nonce"])

    # 2) Sertifika doğrulama
    client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
    if not verify_cert(client_cert, ca_cert):
        hs_logger.error("Client sertifika doğrulaması başarısız. Bağlantı kapatılıyor.")
        conn.close()
        return None, None

    hs_logger.info("Client sertifikası doğrulandı.")

    # Client ECDH public key’i deserialize edelim
    client_pub_key = serialization.load_der_public_key(client_ecdh_pub_bytes)

    # 3) Server ECDH anahtar çifti üret
    server_ecdh_priv = server_priv  # aslında ECDH için ayrı bir anahtar olmalı. Bu örnekte server_priv’ı kullanıyoruz.
    # Ama normalde ECDH için ayrı bir EC private key üretin. Bu örnek daha basit olsun diye bu şekilde ele alacağız.
    server_ecdh_pub = server_ecdh_priv.public_key()

    # 4) Server Hello: Sertifika + ECDH public key + nonce
    server_nonce = os.urandom(16)
    payload = {
        "cert": base64.b64encode(server_cert.public_bytes(serialization.Encoding.PEM)).decode(),
        "ecdh_pub": base64.b64encode(
            server_ecdh_pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode(),
        "nonce": base64.b64encode(server_nonce).decode(),
    }
    payload_json = json.dumps(payload).encode()
    conn.sendall(payload_json)

    hs_logger.info("Server Hello paketi gönderildi.")

    # 5) Ortak secret’i türetelim
    raw_secret = derive_shared_secret(server_ecdh_priv, client_pub_key)
    # Bilgilendirme: Gerçek hayatta server_priv anahtarı ECDH için bir EC anahtarı olmalıydı. Burada prototip amaçlı kolaylaştırdık.

    # HKDF ile enc_key ve mac_key üret
    # “info” olarak hem client_nonce hem server_nonce’i katmak iyi olur:
    info = client_nonce + server_nonce
    enc_key, mac_key = kdf_expand_shared_secret(raw_secret, info=info)

    hs_logger.info("Shared secret ve simetrik anahtarlar türetildi.")
    return enc_key, mac_key


# ----------------------------
# 3) Şifreli-MAC’li Metin Alma İşlevi
# ----------------------------
def receive_encrypted_message(conn, enc_key: bytes, mac_key: bytes):
    """
    Client’tan gelen veriyi alır, önce AES decrypte eder, sonra HMAC doğrular.
    Format: [4 byte uzunluk][iv+ciphertext][32 byte HMAC tag]
    """
    # 4 byte’lık big-endian uzunluk oku
    raw_len = conn.recv(4)
    if len(raw_len) < 4:
        return None
    total_len = int.from_bytes(raw_len, "big")

    # Tam toplam veriyi oku (iv+ciphertext + hmac)
    data = b""
    while len(data) < total_len:
        chunk = conn.recv(total_len - len(data))
        if not chunk:
            return None
        data += chunk

    iv_ciphertext = data[:-32]
    recv_tag = data[-32:]

    # 1) AES çöz, 2) HMAC doğrula
    plaintext_packed = aes_decrypt(enc_key, iv_ciphertext)  # Bu, HMAC + gerçek metin olarak geldi
    tag_of_plain = plaintext_packed[:32]
    actual_plain = plaintext_packed[32:]

    # HMAC’ı kontrol et
    if not verify_hmac(mac_key, actual_plain, tag_of_plain):
        msg_logger.error("HMAC doğrulaması başarısız. Mesaj işlenmiyor.")
        return None

    msg_logger.info(f"Alınan mesaj: {actual_plain.decode()}")
    return actual_plain.decode()


# ----------------------------
# 4) Basit İşlev: Server Dinleme ve Metin Çözme
# ----------------------------
def start_server(host="localhost", port=9000):
    """
    Server soketi açar, client’ı kabul eder, handshake yapar, sonra sırayla metinler alır.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        hs_logger.info(f"Server dinlemede: {host}:{port}")
        conn, addr = s.accept()
        with conn:
            hs_logger.info(f"Client bağlandı: {addr}")
            enc_key, mac_key = server_handshake(conn)
            if enc_key is None:
                return

            # Metinleri dinle
            while True:
                plaintext = receive_encrypted_message(conn, enc_key, mac_key)
                if plaintext is None:
                    break
                print(f"[Client]: {plaintext}")

            hs_logger.info("Client bağlantısı kapandı.")
            

# server/utils.py

import base64
import os

# ... (diğer importlar, log ayarları, vs.)

def save_received_image(plaintext: str, save_dir: str = "server/received_images"):
    """
    Handshake sonrası çözümlenen plaintext metnini kontrol eder.
    Başında `__IMG__` marker’ı varsa, Base64’ü decode edip diske kaydeder.
    """
    marker = "__IMG__"
    if not plaintext.startswith(marker):
        return False  # Bu bir resim mesajı değil

    # Örnek format: "__IMG__dosyaadi.png::iVBORw0KGgoAAAANS..."
    try:
        # 1) Marker’ı at, kalan string'i iki parçaya ("dosyaadi.png", "b64veri") ayır
        without_marker = plaintext[len(marker):]            # "dosyaadi.png::iVBORw0K..."
        filename, b64_str = without_marker.split("::", 1)
    except Exception as e:
        # Yanlış format
        return False

    # 2) save_dir dizini yoksa oluştur
    os.makedirs(save_dir, exist_ok=True)

    # 3) Base64 string’i tekrar byte dizisine çevir
    image_data = base64.b64decode(b64_str.encode("utf-8"))

    # 4) Dosyayı diske yaz
    out_path = os.path.join(save_dir, filename)
    with open(out_path, "wb") as img_f:
        img_f.write(image_data)

    return True

def start_server(host="localhost", port=9000):
    """
    Server dinleme ve gelen verileri işleme (mesaj/metin ya da resim) akışı.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        hs_logger.info(f"Server dinlemede: {host}:{port}")
        conn, addr = s.accept()
        with conn:
            hs_logger.info(f"Client bağlandı: {addr}")
            enc_key, mac_key = server_handshake(conn)
            if enc_key is None:
                return

            # Ana döngü: gelen her paketi al, şifre çöz, HMAC kontrol et, sonra işleme al
            while True:
                plaintext = receive_encrypted_message(conn, enc_key, mac_key)
                if plaintext is None:
                    break

                # 1) Önce resim mi kontrol et:
                if save_received_image(plaintext):
                    msg_logger.info("Bir resim alındı ve kaydedildi.")
                    print("[Server] Resim alındı ve diske yazıldı.")
                    continue

                # 2) Normal metin mesajı ise:
                msg_logger.info(f"Alınan metin: {plaintext}")
                print(f"[Client]: {plaintext}")

            hs_logger.info("Client bağlantısı kapandı.")
