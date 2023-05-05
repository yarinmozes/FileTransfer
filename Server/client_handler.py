#client_handler.py
import sqlite3
import datetime
import db_handler
import uuid
from datetime import datetime



class Client:
    def __init__(self, CID, Name, PublicKey, LastSeen, AES):
        self.CID = CID
        self.Name = Name
        self.PublicKey = PublicKey
        self.LastSeen = LastSeen
        self.AES = AES
        self.failures = 0;

    
    def print_client_info(self):
        print(f"Client ID: {self.CID}")
        print(f"Name: {self.Name}")
        print(f"Public Key: {self.PublicKey}")
        print(f"Last Seen: {self.LastSeen}")
        print(f"AES Key: {self.AES}")


    #Registers the client in the dictionary and database.
    def client_registration(self,name,db_instance):
        print(f"Received registration request from client {name}")
        self.Name = name
        #Checks whether the client is registered in the database
        if db_instance.client_exists_by_name(self.Name):
            print(f"Client: {self.Name} is already exists in the database.")
            return False
        new_cid = uuid.uuid4().bytes
        self.CID = new_cid
        self.LastSeen= datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # add the new client to the clients table in the database
        db_instance.add_client(self)
        self.print_client_info()
        return True
    #Handling a reconnect request
    def client_reconnect(self,name,db_instance):
        print(f"Received reconnect request from client {name}")
        self.Name = name
        #Checks whether the client is registered in the database
        if db_instance.client_exists_by_name(self.Name):
            print(f"Client: {self.Name} is exists in the database.")
            return True
        return False

    #Handles a request to send a public key
    def client_received_public_key(self,name,public_key,db_instance):
        print(f"Received request to send a public key to the server from the client {name}")
        self.Name = name
        if db_instance.client_exists_by_name(self.Name):
            print(f"Client: {self.Name} is exists in the database. ")
            return db_instance.update_client_public_key(self,public_key)
        print(f"The server could not find the client {name} in the database and therefore cannot receive the public key")
        return False
    #Handles a request to send an encrypted file
    def client_handle_received_file(self,file,db_instance):
        print(f"Received request to send the file {file.fileName} to the server")
        db_instance.add_file(file)
    #Handles a request for confirmation of sending the file
    def confirms_receiving_file(self,fileName,db_instance):
        return db_instance.update_file_verified(fileName,True)

            



    

      