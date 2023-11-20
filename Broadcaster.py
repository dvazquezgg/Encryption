import socket
import threading
from Cryptography import *

def create_message():
    message = input("Enter your message: ")
    return message

def server(host, port):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")

    while True:
        client, addr = server_socket.accept()
        print(f"Connection from {addr}")

        threading.Thread(target=handle_client, args=(client,)).start()

def handle_client(client_socket):
    while True:
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            break
        print(f"Received message: {data}")

    client_socket.close()

def client(name, host, port):

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    while True:
        message = create_message()
        if message == "quit":
            break
        if message == "key":
            my_private_key, my_public_key = generate_key_pair()
            save_key_to_file(my_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ), 'my_public_key.pem')
            save_key_to_file(my_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ), 'my_private_key.pem')
            pub_key = my_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            message = f"[key] = {pub_key}"
        if name == "":
            origin = socket.gethostname()
        else:
            origin = name
        message = f"{origin}: {message}"
        client_socket.send(message.encode('utf-8'))

    client_socket.close()

if __name__ == "__main__":

    # Alice generates her key pair
    alice_private_key, alice_public_key = generate_key_pair()

    # Bob generates his key pair
    bob_private_key, bob_public_key = generate_key_pair()

    # Alice saves her public key to a file
    save_key_to_file(alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), 'alice_public_key.pem')

    # Bob saves his public key to a file
    save_key_to_file(bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), 'bob_public_key.pem')

    # Alice loads Bob's public key from the file
    loaded_bob_public_key = serialization.load_pem_public_key(
        open('bob_public_key.pem', 'rb').read()
    )

    # Alice saves her private key to a file
    save_key_to_file(alice_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), 'alice_private_key.pem')

    # Bob saves his private key to a file
    save_key_to_file(bob_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), 'bob_private_key.pem')

    # Bob loads Alice's public key from the file
    loaded_alice_public_key = serialization.load_pem_public_key(
        open('alice_public_key.pem', 'rb').read()
    )

    # Alice signs a message
    message = b"Hello, Bob!"
    signature = sign_message(message, alice_private_key)

    # Bob verifies the signature using Alice's public key
    if verify_signature(message, signature, loaded_alice_public_key):
        print("Signature verified. Message is authentic.")
    else:
        print("Signature verification failed. Message may be tampered.")


    # Obtain the connection IP address from the computer
    IP_Address = socket.gethostbyname(socket.gethostname())
    print(f"IP Address: {IP_Address}")

    host = IP_Address
    port = 12345

    # Do you want to be the server or the client?
    while True:
        role = input("Do you want to be the server or the client? ")
        if role == "server":
            server(host, port)
            server_thread = threading.Thread(target=server)
            server_thread.start()
            break
        elif role == "client":
            name = input("Enter your name: ")
            host = input("Enter the host server: ")
            port = int(input("Enter the port: "))
            client(name, host, port)
            client_thread = threading.Thread(target=client)
            client_thread.start()
            break
        else:
            print("Please enter either 'server' or 'client'")




