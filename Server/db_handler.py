#db_handler.py
import sqlite3
import threading
import client_handler
from datetime import datetime

SQL_FILE_NAME = "server.db"

class Database:

    def __init__(self):
        # initialize the database connection
        self.conn = sqlite3.connect(SQL_FILE_NAME, check_same_thread=False)
        self.cursor = self.conn.cursor()
        # initialize the dictionaries
        self.files = {}
        self.clients =  {}
        self.file_lock = threading.Lock()
        
    def create_clients_tables(self):
        # check if the clients table exist
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
        result = self.cursor.fetchone()
        if not result:
            # create the clients table
            self.cursor.execute('''CREATE TABLE clients
                       (ID BLOB(16) PRIMARY KEY,
                        Name TEXT(255) NOT NULL,
                        PublicKey BLOB(160) NOT NULL,
                        LastSeen DATETIME NOT NULL,
                        AesKey BLOB(16) NOT NULL)''')
            print("The client table has been created")
            return True
        print("The client table already exists, updates the dictionary with the existing data")
        return False
        
    def create_files_tables(self):    
        # Check if the files tables exist
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
        result = self.cursor.fetchone()
        if not result:
            # create the files table
            self.cursor.execute('''CREATE TABLE files
                        (ID BLOB(16) PRIMARY KEY,
                        FileName TEXT NOT NULL,
                        PathName TEXT NOT NULL,
                        Verified BOOLEAN NOT NULL)''')
            print("The files table has been created")
            return True
        print("The files table already exists, updates the dictionary with the existing data")
        return False
        
    
    def update_clients_dict(self):
        with self.file_lock:
            try:
                self.cursor.execute("SELECT * FROM clients")
                rows = self.cursor.fetchall()
                for row in rows:
                    client = client_handler.Client(row[0], row[1], row[2], row[3], row[4])
                    self.clients[client.CID] = client
                print("The client dictionary has been updated with the existing data")
                return True
            except Exception:
                return False

    def update_files_dict(self):
        with self.file_lock:
            try:
                self.cursor.execute("SELECT * FROM files")
                rows = self.cursor.fetchall()
                for row in rows:
                    file = File(row[0], row[1], row[2], row[3])
                    self.files[file.ID] = file
                print("The files dictionary has been updated with the existing data")
                return True
            except Exception:
                return False


    def add_client(self, client):
        self.cursor.execute("INSERT INTO clients (ID, Name, PublicKey, LastSeen, AesKey) \
                        VALUES (?, ?, ?, ?, ?)",
                       (client.CID, client.Name, client.PublicKey, client.LastSeen, client.AES))
        self.conn.commit()
        self.clients[client.CID] = client
        print(f"Client: {client.Name} has successfully registered to the server.")
    
    
    def client_exists_by_id(self, client):
        # check if a client exists in the clients table in the database
        self.cursor.execute("SELECT ID FROM clients WHERE ID=?" , (client.CID))
        result = self.cursor.fetchone()
        if result and client.Name in self.clients:
            return True
        else:
            return False

    def file_exists_by_id(self, file):
        # check if a file exists in the files table in the database
        self.cursor.execute("SELECT id FROM files WHERE id=?", (file.ID,))
        result = self.cursor.fetchone()
        if result and file.ID in self.files:
            return True
        else:
            return False

    def file_exists_by_name(self, fileName):
        # Check if the file exists in the files table in the database based on the file name
        self.cursor.execute("SELECT FileName FROM files WHERE FileName=?", (fileName,))
        result = self.cursor.fetchone()
        if result:
            return True
        else:
            return False
        
    def client_exists_by_name(self, name):
        # Check if a client exists in the clients table in the database based on the name
        self.cursor.execute("SELECT Name FROM clients WHERE Name=?", (name,))
        result = self.cursor.fetchone()
        if result:
            return True
        else:
            return False


    def update_client_aes(self, client):
        try:
            # update a client's AES in the clients table in the database
            self.cursor.execute("UPDATE clients SET aes=? WHERE id=?", (client.AES, client.CID))
            self.conn.commit()

            # update a client's AES in the clients dictionary
            if client.CID in self.clients:
                self.clients[client.CID].AES = client.AES

            print("AES updated successfully!")
            return True

        except Exception as e:
            print("Error updating AES:", str(e))
            return False
    

    def update_client_public_key(self, client,public_key):
        try:
            # update a client's public key in the clients table in the database
            self.cursor.execute("UPDATE clients SET PublicKey=? WHERE id=?", (public_key, client.CID))
            self.conn.commit()

            # update a client's public key in the clients dictionary
            if client.CID in self.clients:
                self.clients[client.CID].public_key = public_key

            print("public key updated successfully!")
            return True

        except Exception as e:
            print("Error updating public key:", str(e))
            return False

         
    
    def add_file(self, file):
        # add a file to the files table in the database
        self.cursor.execute("INSERT INTO files (id, file_name, path_name, verified) VALUES (?, ?, ?, ?)", 
                            (file.ID, file.file_name, file.path_name, file.verified))
        self.conn.commit()

        # add a file to the files dictionary
        self.files[file.ID] = file
    
    def update_client_last_seen(self, client):
        last_seen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # update the client's last seen value to the specified date and time in the database
        self.cursor.execute("UPDATE clients SET LastSeen = ? WHERE id = ?", (last_seen, client.CID))
        self.conn.commit()

        # update the client's last seen value in the dictionary
        self.clients[client.CID].LastSeen  = last_seen


    def update_file_verified(self, file_id, verified):
        try:
            # update the verified value in the files table in the database
            self.cursor.execute("UPDATE files SET verified=? WHERE id=?", (verified, file_id))
            self.conn.commit()

            # update the verified value in the files dictionary
            if file_id in self.files:
                self.files[file_id].verified = verified

            print("Verified value updated successfully!")
            return True

        except Exception as e:
            print("Error updating verified value:", str(e))
            return False

    def get_client_aes(self, client):
        if client.CID in self.clients:
            return self.clients[client.CID].AES
        else:
            return None


    def get_client_public_key(self, client):
        if client.CID in self.clients:
            return self.clients[client.CID].public_key
        else:
            return None



class File:
    def __init__(self, ID, file_name, path_name, verified):
        self.ID = ID
        self.file_name = file_name
        self.path_name = path_name
        self.verified = verified
    
    def get_client_by_id(self, CID):
    # fetch a client by its id from the clients dictionary
         self.clients.get(CID)
