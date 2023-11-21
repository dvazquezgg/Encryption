import socket
import threading
from queue import Queue

MAX_MESSAGES = 20

def server():
    # Obtain the connection IP address from the computer
    IP_Address = socket.gethostbyname(socket.gethostname())
    print(f"IP Address: {IP_Address}")

    host = IP_Address
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")

    message_queue = Queue(maxsize=MAX_MESSAGES)

    def broadcast_messages():
        while True:
            if not message_queue.empty():
                message = message_queue.get()
                for client_socket in clients:
                    try:
                        client_socket.send(message.encode('utf-8'))
                    except socket.error:
                        # Handle a disconnected client
                        clients.remove(client_socket)

    threading.Thread(target=broadcast_messages, daemon=True).start()

    while True:
        client, addr = server_socket.accept()
        print(f"Connection from {addr}")

        threading.Thread(target=handle_client, args=(client, message_queue)).start()

def handle_client(client_socket, message_queue):
    clients.append(client_socket)

    while True:
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            break

        # Add the received message to the queue
        message_queue.put(data)

        if message_queue.qsize() > MAX_MESSAGES:
            message_queue.get()  # Remove the oldest message if the queue is full

    # Client disconnected, remove from the list of clients
    clients.remove(client_socket)
    client_socket.close()

if __name__ == "__main__":
    clients = []  # List to store client sockets
    server_thread = threading.Thread(target=server)
    server_thread.start()
