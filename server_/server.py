# server/server.py
from server.utils import start_server

if __name__ == "__main__":
    # Host ve port’ı ihtiyacınıza göre değiştirebilirsiniz.
    start_server(host="localhost", port=9000)
