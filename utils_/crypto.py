# utils/crypto.py
import os
import logging
from cryptography import x509
import datetime
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


logger = logging.getLogger("crypto_utils")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
logger.addHandler(handler)


# ----------------------------
# 1) EC Anahtar Çifti Üretimi
# ----------------------------
def generate_ec_keypair(curve=ec.SECP256R1()):
    """
    EC (ECDSA/ECDH) anahtar çifti üretir.
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


# ----------------------------
# 2) PEM Formatında Anahtar Kaydetme / Yükleme
# ----------------------------
def save_private_key_to_pem(private_key, filepath, password=None):
    """
    EC özel anahtarını PEM'e kaydeder. Eğer password verilirse şifreler.
    """
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    logger.debug(f"Private key saved to {filepath}")


def load_private_key_from_pem(filepath, password=None):
    """
    PEM’den EC özel anahtarını yükler.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    private_key = serialization.load_pem_private_key(data, password=password)
    logger.debug(f"Private key loaded from {filepath}")
    return private_key


def save_public_cert_to_pem(cert, filepath):
    """
    X.509 sertifikayı PEM’e kaydeder.
    """
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(filepath, "wb") as f:
        f.write(pem)
    logger.debug(f"Certificate saved to {filepath}")


def load_public_cert_from_pem(filepath):
    """
    PEM’den X.509 sertifika yükler.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data)
    logger.debug(f"Certificate loaded from {filepath}")
    return cert


# ----------------------------
# 3) Basit X.509 Sertifika Oluşturma (Self-signed veya CA-signed)
# ----------------------------
def create_self_signed_cert(private_key, common_name: str, days_valid=365):
    """
    Kendi kendine imzalı (self-signed) X.509 sertifika üretir.
    """
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())              
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    cert = cert_builder.sign(private_key, hashes.SHA256())
    return cert


def create_cert_signed_by_ca(
    public_key, ca_private_key, ca_cert, subject_name: str, days_valid=365
):
    """
    CA’nın özel anahtarıyla verilen public_key için X.509 sertifika oluşturur.
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = ca_cert.subject
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    return cert


# ----------------------------
# 4) Sertifika Doğrulama
# ----------------------------
def verify_cert(cert: x509.Certificate, ca_cert: x509.Certificate):
    """
    Bir sertifikanın CA tarafından imzalı olup olmadığını doğrular.
    """
    try:
        # CA’nın public key’i ile sertifika imzasını kontrol et
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        logger.debug(f"Certificate for {cert.subject.rfc4514_string()} verified successfully.")
        return True
    except Exception as e:
        logger.error(f"Certificate verification failed: {e}")
        return False


# ----------------------------
# 5) ECDH ile Ortak Anahtar (Shared Secret) Hesaplama
# ----------------------------
def derive_shared_secret(own_private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey):
    """
    ECDH ile ortak (raw) secret döner.
    """
    raw_secret = own_private_key.exchange(ec.ECDH(), peer_public_key)
    logger.debug(f"Derived raw ECDH secret: {raw_secret.hex()[:16]}...")
    return raw_secret


# ----------------------------
# 6) HKDF ile Sembolik Anahtarlar (Encryption Key, MAC Key) Türetme
# ----------------------------
def kdf_expand_shared_secret(raw_secret: bytes, info: bytes = b"handshake data", length: int = 64):
    """
    HKDF kullanarak raw_secret’den yeterince uzun (örneğin 64 byte) bir key material elde eder.
    Sonra ilk 32 byte’ı AES şifreleme anahtarı, sonraki 32 byte’ı HMAC anahtarı olarak kullanırız.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    key_material = hkdf.derive(raw_secret)
    enc_key = key_material[:32]
    mac_key = key_material[32:64]
    logger.debug(f"HKDF-derived enc_key: {enc_key.hex()[:16]}..., mac_key: {mac_key.hex()[:16]}...")
    return enc_key, mac_key


# ----------------------------
# 7) AES-CBC Şifreleme / Çözme (IV sabit uzunlukta 16 byte)
# ----------------------------
def aes_encrypt(key: bytes, plaintext: bytes):
    """
    AES-CBC ile rastgele bir IV üreterek plaintext’i şifreler. 
    Dönen: iv (16 byte) + ciphertext.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # PKCS7 padding uygulamak için:
    pad_len = 16 - (len(plaintext) % 16)
    padding_bytes = bytes([pad_len] * pad_len)
    padded = plaintext + padding_bytes

    ct = encryptor.update(padded) + encryptor.finalize()
    logger.debug(f"AES encrypt: iv={iv.hex()[:8]}..., ct_len={len(ct)}")
    return iv + ct


def aes_decrypt(key: bytes, iv_ciphertext: bytes):
    """
    AES-CBC çözme. `iv_ciphertext` 16 byte IV + ciphertext olarak gelir.
    PKCS7 padding’i çıkarır, doğruları döner.
    """
    iv = iv_ciphertext[:16]
    ct = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    # PKCS7 padding’i çıkar
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    logger.debug(f"AES decrypt: iv={iv.hex()[:8]}..., pt_len={len(plaintext)}")
    return plaintext


# ----------------------------
# 8) HMAC-SHA256 Hesaplama ve Doğrulama
# ----------------------------
def compute_hmac(mac_key: bytes, data: bytes):
    """
    HMAC-SHA256 hesaplar.
    """
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)
    tag = h.finalize()
    logger.debug(f"Computed HMAC: {tag.hex()[:16]}...")
    return tag


def verify_hmac(mac_key: bytes, data: bytes, tag: bytes):
    """
    HMAC doğrular. Başarısızsa exception atar.
    """
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        logger.debug("HMAC verification succeeded.")
        return True
    except Exception as e:
        logger.error(f"HMAC verification failed: {e}")
        return False
