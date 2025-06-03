# device/device.py
import socket
import time
from device.utils import device_handshake, send_encrypted_message

def start_client(server_host="localhost", server_port=9000):
    """
    Server’a bağlan, handshake yap, sonra console’dan girilen metni şifreleyip gönder.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_host, server_port))
        print(f"Sunucuya bağlanıldı: {server_host}:{server_port}")

        enc_key, mac_key = device_handshake(sock)
        if enc_key is None:
            print("Handshake başarısız, çıkılıyor.")
            return

        print("Handshake başarılı. Artık şifreli-MAC’li metin gönderilebilir.")
        while True:
            message = input("Göndermek istediğiniz metni yazın ('exit' ile çık): ")
            if message.lower() == "exit":
                break
            # 1 saniye bekleyelim (örnek zamanlama, opsiyonel)
            time.sleep(0.2)
            send_encrypted_message(sock, enc_key, mac_key, message)

        print("Client çıkıyor.")


if __name__ == "__main__":
    start_client(server_host="localhost", server_port=9000)
