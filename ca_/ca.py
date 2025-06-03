# ca/ca.py
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from utils.crypto import (
    generate_ec_keypair,
    save_private_key_to_pem,
    save_public_cert_to_pem,
    create_self_signed_cert,
)

import datetime

# CA için anahtar ve sertifika yolları
CA_KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(CA_KEYS_DIR, exist_ok=True)
CA_PRIVATE_KEY_PATH = os.path.join(CA_KEYS_DIR, "ca_private_key.pem")
CA_PUBLIC_CERT_PATH = os.path.join(CA_KEYS_DIR, "ca_public_cert.pem")


def initialize_ca():
    """
    Eğer CA anahtarı yoksa üret, self-signed sertifika oluştur.
    """
    if not os.path.exists(CA_PRIVATE_KEY_PATH) or not os.path.exists(CA_PUBLIC_CERT_PATH):
        print("CA anahtarları bulunamadı. Yeni CA anahtar/sertifika üretiliyor...")
        # 1) EC anahtar çifti
        ca_priv, ca_pub = generate_ec_keypair()

        # 2) Kendinden imzalı (self-signed) sertifika
        ca_cert = create_self_signed_cert(ca_priv, common_name="MySimpleCA", days_valid=3650)

        # 3) Dosyalara kaydet
        save_private_key_to_pem(ca_priv, CA_PRIVATE_KEY_PATH, password=None)
        save_public_cert_to_pem(ca_cert, CA_PUBLIC_CERT_PATH)
        print(f"CA anahtarları ve sertifika kaydedildi:\n - {CA_PRIVATE_KEY_PATH}\n - {CA_PUBLIC_CERT_PATH}")
    else:
        print("CA anahtarları zaten mevcut. İptal ediliyor.")


if __name__ == "__main__":
    initialize_ca()
