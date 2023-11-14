import socket
import json
import time
import sys


class Client:
    def __init__(self, config_file):
        with open(config_file, 'r') as file:
            self.config = json.load(file)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.socket.connect((self.config['server']['ip'], self.config['server']['port']))
        registration_data = json.dumps({"id": self.config['id'], "password": self.config['password']})
        self.socket.send(registration_data.encode())
        response = self.socket.recv(1024).decode()
        print(f"Server response: {response}")

    def perform_actions(self):
        for action in self.config['actions']['steps']:
            if action.startswith("INCREASE") or action.startswith("DECREASE"):
                command, amount = action.split()
                amount = int(amount)
                action_data = json.dumps(
                    {"id": self.config['id'], "password": self.config['password'], "action": command, "amount": amount})
                self.socket.send(action_data.encode())
                response = self.socket.recv(1024).decode()
                print(f"Server response: {response}")
                time.sleep(self.config['actions']['delay'])

    def start(self):
        self.connect()
        self.perform_actions()
        self.socket.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <config_file>")
        sys.exit(1)

    client = Client(sys.argv[1])
    client.start()
