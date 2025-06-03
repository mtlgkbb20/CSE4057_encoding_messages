# device/device.py
import socket
import time
from device.utils import device_handshake, send_encrypted_message, send_encrypted_image
import os

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
        # device/device.py içinde, mesaj döngüsünde (send loop):
        while True:
            choice = input("1) Metin gönder\n2) Resim gönder\n3) Çıkış\nSeçiminiz: ")
            if choice == "3":
                break
            elif choice == "1":
                message = input("Göndermek istediğiniz metni yazın: ")
                send_encrypted_message(sock, enc_key, mac_key, message)
            elif choice == "2":
                path = input("Göndermek istediğiniz resmin tam yolu: ")
                if os.path.exists(path):
                    send_encrypted_image(sock, enc_key, mac_key, path)
                else:
                    print("Dosya bulunamadı, lütfen geçerli bir yol girin.")
            else:
                print("Geçersiz seçim.")


        print("Client çıkıyor.")


if __name__ == "__main__":
    start_client(server_host="localhost", server_port=9000)
