#response.py
import struct

class Response:
    VERSION = 3

    REGISTER_SUCC = 2100
    REGISTER_FAIL = 2101
    RECIVED_PUBLIC_KEY_SEND_AES = 2102
    FILE_REC_OK_WITH_CRC = 2103
    CONFIRMS_RECIVED_FILE = 2104
    APPROVED_RECONNECT = 2105
    DENIED_RECONNECT = 2106
    GENERAL_ERROR = 2107

    CLIENT_ID_SIZE = 16
    AES_KEY_SIZE = 128
    CONTENT_SIZE_SIZE = 4
    FILE_NAME_SIZE = 255
    CKSUM_SIZE = 4

    #takes aresponse code and a payload size and returns a header as a packed binary string in little-endian byte order.
    @staticmethod
    def build_header(response_code, payload_size):
        return struct.pack("<B H I", Response.VERSION, response_code, payload_size)

    @staticmethod
    def successful_registration(client_id):
        response_code = Response.REGISTER_SUCC
        payload_size = Response.CLIENT_ID_SIZE
        header = Response.build_header(response_code, payload_size)
        print(f"Sending server response {response_code}, registration successful ")
        return header + client_id

    @staticmethod
    def failed_registration(client_id):
        response_code = Response.REGISTER_FAIL
        payload_size = 0
        header = Response.build_header(response_code, payload_size)
        print(f"The server response {response_code} Registration Failed to the client")
        return header

    @staticmethod
    def received_public_key_send_aes(client_id, encrypted_aes_key):
        response_code = Response.RECIVED_PUBLIC_KEY_SEND_AES
        payload_size = Response.CLIENT_ID_SIZE + Response.AES_KEY_SIZE
        header = Response.build_header(response_code, payload_size)
        return header + client_id + encrypted_aes_key
    
    @staticmethod
    def approved_reconnecting(client_id, encrypted_aes_key):

        response_code = Response.APPROVED_RECONNECT
        payload_size = Response.CLIENT_ID_SIZE + Response.AES_KEY_SIZE
        header = Response.build_header(response_code, payload_size)
        encrypted_aes_key_bytes = encrypted_aes_key.to_bytes(16, byteorder='little')

        print(f"The server response  {response_code} Reconnection has been approved to the client")
        return header + client_id + encrypted_aes_key_bytes
        
    @staticmethod
    def denied_reconnecting(client_id):
        response_code = Response.DENIED_RECONNECT
        payload_size = Response.CLIENT_ID_SIZE
        header = Response.build_header(response_code, payload_size)
        print(f"Sending server response {response_code}, Reconnection denied to the client")
        return header + client_id

    @staticmethod
    def public_key_received_sending_aes(client_id, encrypted_aes_key):

        response_code = Response.RECIVED_PUBLIC_KEY_SEND_AES
        payload_size = Response.CLIENT_ID_SIZE + Response.AES_KEY_SIZE
        header = Response.build_header(response_code, payload_size)
        print(f"The server response  {response_code}, Public key received, sending AES key")
        return header + client_id + encrypted_aes_key

    @staticmethod
    def File_received_OK_with_CRC(client_id, contentSize,fileName,cksum):
        response_code = Response.FILE_REC_OK_WITH_CRC 
        payload_size = Response.CLIENT_ID_SIZE + Response.CONTENT_SIZE_SIZE +Response.FILE_NAME_SIZE + Response.CKSUM_SIZE
        header = Response.build_header(response_code, payload_size)
        print(f"The server response  {response_code}, File received OK with CRC")
        return header + client_id + contentSize + fileName + cksum

    @staticmethod
    def Finish_handle_client(client_id):
        response_code = Response.CONFIRMS_RECIVED_FILE
        payload_size = Response.CLIENT_ID_SIZE
        header = Response.build_header(response_code, payload_size)
        print(f"Sending server response {response_code}, Confirms receiving the file ")
        return header + client_id

    @staticmethod
    def General_error():
        response_code = Response.GENERAL_ERROR
        payload_size = 0
        header = Response.build_header(response_code, payload_size)
        print(f"The server response {response_code} General error")
        return header