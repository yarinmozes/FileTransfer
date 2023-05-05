# server.py

from asyncio.windows_events import NULL
import binascii
import socket
import sys
import threading
import traceback
import struct
import logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
from db_handler import Database, File
from client_handler import Client
from response import Response


SERVER_VERSION = 3
DEFAULT_PORT = 1234
PORT_FILE_NAME = "port.info"
CHUNK_SIZE = 1024
REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4
CLIENT_ID_SIZE = 16
VERSION_SIZE = 1
REQ_CODE_SIZE = 2
PAYLOAD_SIZE_SIZE = 4


REGISTER = 1100
SEND_PUBLIC_KEY = 1101
RECONNECT = 1102
SEND_FILE = 1103
CRC_CORRECT = 1104
INVALID_CRC = 1105
BAD_CRC_DONE = 1106

class Server:
    # Initialize the server with a host, port, and other necessary attributes
    def __init__(self,host,port):
        self.port = port
        self.server_socket = None
        self.host = host
        self.client_threads = []
        self.db = Database()

    # Create tables in the database if necessary and run the server
    def run_server(self):
        if not self.db.create_clients_tables():
           if not self.db.update_clients_dict():
                print("Error creating the data structure")
                return 0;
        if not self.db.create_files_tables():
           if not self.db.update_files_dict():
                print("Error creating the data structure")
                return 0;

        # Set up server socket and start listening for connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server version {SERVER_VERSION} is listening on port {self.port} \n")
        #Accept connections from clients and create a thread for each
        while True:
           client_socket, address = self.server_socket.accept()
           print(f"Accepted connection from {address[0]}:{address[1]}")
           client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))

           client_thread.start()
           self.client_threads.append(client_thread)

    def handle_client(self, client_socket):

        # Handle client requests and send appropriate responses
        try:
            while True:
                # Receive request header and unpack it
                header = client_socket.recv(REQUEST_HEADER_SIZE)

                cid, version, request_code_0, request_code_1, payload_size_0, payload_size_1, payload_size_2, payload_size_3 = struct.unpack("<16sB2B4B", header)
                request_code = (request_code_1 << 8) | request_code_0
                payload_size = (payload_size_3 << 24) | (payload_size_2 << 16) | (payload_size_1 << 8) | payload_size_0

                # Receive the payload based on the payload_size
                payload = client_socket.recv(payload_size)

                # Create a new client object
                client = Client(cid, None, NULL, None, NULL)
       
                 
                #Handle the request based on the code
                #Checks the number of CRC failures
                if client.failures > 3:
                    response = Response.Finish_handle_client(client.CID)

                elif request_code == REGISTER:
                    name = payload.decode('ascii').strip('\0')
                    if client.client_registration(name,self.db):
                        response = Response.successful_registration(client.CID)
                    else:
                        response = Response.failed_registration(client.CID)
              
                elif request_code == RECONNECT:
                    name = payload.decode('utf-8')[:payload.index('\x00')+1]

                    if client.client_reconnect(name,self.db):
                        response = Response.approved_reconnecting(client.CID, client.AES)
                    else:
                        response = Response.denied_reconnecting(client.CID)

                elif request_code == SEND_PUBLIC_KEY:
                    name = payload[: -160].decode('ascii').strip('\0')
                    publicKey = payload[-160:]
                    
                    if client.client_received_public_key(name,publicKey,self.db):
                        print(f"The public key of {name} is {publicKey} ")
                        aes = Server.encrypt_aes_key(publicKey)
                        self.db.update_client_aes(aes)
                        response = Response.public_key_received_sending_aes(client.CID,aes)
                    else:
                        response = Response.General_error()
                
                elif request_code==SEND_FILE:
               
                    contentSize = payload[:4]
                    fileName = payload[4: 260].decode('ascii').strip('\0')
                    fileData =payload[260:]
                    decryptFileData = Server.decrypt_file(fileData,self.db.get_client_aes())
                    recFile = File(client.Name,fileName,fileName,False)
                    client.client_handle_received_file(recFile)
                    try:
                       Server.create_file(fileName,decryptFileData) 
                       response = Response.File_received_OK_with_CRC(client.CID, contentSize,fileName,Server.rc32_checksum(fileName))
                    except Exception as e:
                        print(f"Error occurred while processing the file: {fileName}\n{str(e)}")
                        response = Response.General_error()


                elif request_code==CRC_CORRECT:
                    fileName = payload.decode('ascii').strip('\0')
                    if client.confirms_receiving_file(fileName,self.db):
                        response = Response.Finish_handle_client(client.CID)
                    else:
                        response = Response.General_error()
            
                elif request_code==INVALID_CRC:
                    client.failures = client.failures + 1
                   
                    
                elif request_code==BAD_CRC_DONE:
                     response = Response.Finish_handle_client(client.CID)   

                else:
                    print(f"The server does not support the request {request_code}")
                    break
                   

                client_socket.sendall(response)

        except Exception as e:
           print(f"Error handling client: {e}")
           traceback.print_exc()

        finally:
           print("Closing client connection")
           client_socket.close()
        
    def encrypt_aes_key(public_key):
        # Generate 128-bit AES key
        aes_key = os.urandom(16)

        # Encrypt AES key using public key
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return encrypted_aes_key          

    def decrypt_file(encrypted_data, key):
        # Initialize the AES cipher with the given key
        cipher = AES.new(key, AES.MODE_EAX)

        # Get the nonce and tag from the encrypted data
        nonce = encrypted_data[:cipher.nonce_size]
        tag = encrypted_data[-cipher.digest_size:]

        # Decrypt the data using the cipher and the nonce
        encrypted_content = encrypted_data[cipher.nonce_size:-cipher.digest_size]
        decrypted_content = cipher.decrypt_and_verify(encrypted_content, tag)

        return decrypted_content

    def create_file(file_name, content):
        try:
            with open(file_name, 'w') as file:
                file.write(content)
            return True
        except:
            return False

    def crc32_checksum(filename):
        try:
            with open(filename, 'rb') as file:
                buf = file.read()
                crc = binascii.crc32(buf)
                return crc & 0xFFFFFFFF
        except FileNotFoundError:
            print(f"File not found: {filename}")
            sys.exit(1)
        except Exception as e:
            print(f"Error occurred while processing the file: {filename}\n{str(e)}")
            sys.exit(1)


def main():
     
    # Read port number from file
    try:
        with open(PORT_FILE_NAME, "r") as f:    
            port = int(f.read())   
    except FileNotFoundError:
        port = DEFAULT_PORT
        logging.warning(f"Error: Unable to open file: {PORT_FILE_NAME} . Using default port: {DEFAULT_PORT} instead\n" )     

    server = Server('localhost',port)
    server.run_server()

if __name__ == '__main__':
    main()
