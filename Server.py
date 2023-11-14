import socket
import threading
import json


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.clients = {}
        self.lock = threading.Lock()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((ip, port))
        self.server_socket.listen()

    def listen(self):
        print(f"Server listening on {self.ip}:{self.port}")
        while True:
            client, address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode()
                if not message:
                    break
                response = self.process_request(message)
                client_socket.send(response.encode())
            except:
                break

    def process_request(self, message):
        data = json.loads(message)
        client_id = data['id']
        password = data['password']
        action = data.get('action')
        amount = int(data.get('amount', 0))

        with self.lock:
            if client_id not in self.clients or self.clients[client_id]['password'] == password:
                if client_id not in self.clients:
                    self.clients[client_id] = {'password': password, 'counter': 0}
                if action == 'INCREASE':
                    self.clients[client_id]['counter'] += amount
                elif action == 'DECREASE':
                    self.clients[client_id]['counter'] -= amount
                self.log_counter_change(client_id)
                return f"ACK: Counter updated to {self.clients[client_id]['counter']}"
            else:
                return "ERROR: Invalid credentials"

    def log_counter_change(self, client_id):
        with open("server_log.txt", "a") as file:
            file.write(f"{client_id}: {self.clients[client_id]['counter']}\n")


if __name__ == "__main__":
    try:
        server = Server("127.0.0.1", 65431)
        server.listen()
    except OSError as e:
        print(f"Error starting server: {e}")
    except KeyboardInterrupt:
        print("Server shutting down.")
