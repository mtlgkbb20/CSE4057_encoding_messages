# device/utils.py
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
    compute_hmac,
)

# ----------------------------
# Logging Ayarları
# ----------------------------
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Handshake için log
hs_logger = logging.getLogger("device_handshake")
hs_logger.setLevel(logging.DEBUG)
hs_handler = logging.FileHandler(os.path.join(LOG_DIR, "handshake.log"))
hs_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
hs_logger.addHandler(hs_handler)

# Mesajlar için log
msg_logger = logging.getLogger("device_messages")
msg_logger.setLevel(logging.DEBUG)
msg_handler = logging.FileHandler(os.path.join(LOG_DIR, "messages.log"))
msg_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
msg_logger.addHandler(msg_handler)


# ----------------------------
# 1) Anahtar & Sertifika Yükleme
# ----------------------------
DEVICE_KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(DEVICE_KEYS_DIR, exist_ok=True)
DEVICE_PRIVATE_KEY_PATH = os.path.join(DEVICE_KEYS_DIR, "device_private_key.pem")
DEVICE_PUBLIC_CERT_PATH = os.path.join(DEVICE_KEYS_DIR, "device_public_cert.pem")

CA_PUBLIC_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "ca", "keys", "ca_public_cert.pem")


def load_device_credentials():
    """
    Device’in özel anahtarını ve sertifikasını (CA imzalı) yükler.
    """
    device_priv = load_private_key_from_pem(DEVICE_PRIVATE_KEY_PATH)
    device_cert = load_public_cert_from_pem(DEVICE_PUBLIC_CERT_PATH)
    ca_cert = load_public_cert_from_pem(CA_PUBLIC_CERT_PATH)
    return device_priv, device_cert, ca_cert


# ----------------------------
# 2) Handshake (El Sıkışma) İşlemi (Cihaz => Sunucu)
# ----------------------------
def device_handshake(sock):
    """
    1) Cihaz kendi sertifikasını, ECDH public key’ini ve nonce’u JSON olarak server’a yollar.
    2) Server’dan Hello paketi alır: içinde sertifika, ecdh_pub, nonce var.
    3) Server sertifikasını CA ile doğrular.
    4) ECDH raw secret + HKDF ile simetrik anahtarları türetir.
    5) Elde edilen enc_key, mac_key return edilir.
    """
    device_priv, device_cert, ca_cert = load_device_credentials()

    # 1) Cihaz ECDH anahtar çifti üret (basitçe device_priv’ı kullanalım, pratikte ayrı olmalı)
    device_ecdh_priv = device_priv
    device_ecdh_pub = device_ecdh_priv.public_key()

    # Rastgele bir nonce oluştur
    device_nonce = os.urandom(16)

    # İlk Hello: sertifika + ECDH public key + nonce
    payload = {
        "cert": base64.b64encode(device_cert.public_bytes(serialization.Encoding.PEM)).decode(),
        "ecdh_pub": base64.b64encode(
            device_ecdh_pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode(),
        "nonce": base64.b64encode(device_nonce).decode(),
    }
    payload_json = json.dumps(payload).encode()
    sock.sendall(payload_json)
    hs_logger.info("Device Hello paketi gönderildi.")

    # 2) Server Hello’yu al
    data = sock.recv(8192)
    server_hello = json.loads(data.decode())
    server_cert_bytes = base64.b64decode(server_hello["cert"])
    server_ecdh_pub_bytes = base64.b64decode(server_hello["ecdh_pub"])
    server_nonce = base64.b64decode(server_hello["nonce"])

    # 3) Sertifika doğrulama
    server_cert = x509.load_pem_x509_certificate(server_cert_bytes)
    if not verify_cert(server_cert, ca_cert):
        hs_logger.error("Server sertifika doğrulaması başarısız. Bağlantı kapatılıyor.")
        sock.close()
        return None, None

    hs_logger.info("Server sertifikası doğrulandı.")

    # Server’ın ECDH public key’ini deserialize et
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    server_pub_key = load_der_public_key(server_ecdh_pub_bytes)

    # 4) Ortak secret’i türet
    raw_secret = derive_shared_secret(device_ecdh_priv, server_pub_key)
    info = device_nonce + server_nonce
    enc_key, mac_key = kdf_expand_shared_secret(raw_secret, info=info)

    hs_logger.info("Shared secret ve simetrik anahtarlar türetildi.")
    return enc_key, mac_key


# ----------------------------
# 3) Şifreli-MAC’li Metin Gönderme
# ----------------------------
def send_encrypted_message(sock, enc_key: bytes, mac_key: bytes, message: str):
    """
    plaintext -> [HMAC(plaintext) || plaintext] -> AES-CBC ile şifrele -> [iv+ciphertext] 
    -> sonuna HMAC tag ekle -> toplam boyutu 4 byte prefix ile gönder.
    """
    # 1) Mesajın HMAC’ını hesapla
    plaintext_bytes = message.encode()
    tag = compute_hmac(mac_key, plaintext_bytes)

    # 2) Tepegörü: [32 byte HMAC || mesaj bytes]
    packed = tag + plaintext_bytes

    # 3) AES encrypt (iv+ciphertext)
    iv_cipher = aes_encrypt(enc_key, packed)

    # 4) Verinin tamamı -> sonuna HMAC ekle
    send_tag = compute_hmac(mac_key, iv_cipher)
    final_blob = iv_cipher + send_tag

    # 5) 4 byte toplam uzunluk prefix + veriyi gönder
    total_len = len(final_blob)
    sock.sendall(total_len.to_bytes(4, "big") + final_blob)
    msg_logger.info(f"Şifreli mesaj gönderildi: “{message}”")


