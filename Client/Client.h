//yarin mozes
//client.h
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/crc.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <osrng.h>
#include <rsa.h>
#include <aes.h>
#include <files.h>
#include <crc.h>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <base64.h>
#include <modes.h>
#include <filters.h>
#include <sha.h>
#include <oaep.h>


using boost::asio::ip::tcp;

//Structure of a response from the server
struct Response {
    uint8_t server_version;
    uint16_t response_code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
    Response(uint16_t response_code, const std::vector<uint8_t>& payload)
        : server_version(3), response_code(response_code), payload_size(payload.size()), payload(payload) {
    }
};
//Structure of a server request
struct Request {
    std::array<uint8_t, 16> cid;
    uint8_t version = 3;
    std::array<uint8_t, 2> request_code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
};


class Client {
public:

    // Constructor for the Client class
    Client(boost::asio::io_context& io_context,
        const std::string& ip,
        int port,
        const std::string& clientName,
        const std::string& filePath);

    
    std::string read();// Reads RESPONSE_HEADER_SIZE bytes from the server
    std::string read(std::size_t n);// Reads 'n' bytes from the server
    void registerClient();// Registers the client with the server
    void reconnectClient();// Reconnects the client to the server
    void sendRequest(const std::vector<uint8_t>& request);// Sends a request to the server
    Response receiveResponse();// Receives a response from the server
    void printServerResponse(const Response& response);// Prints the server response to the console
    void generateRSAKeys();// Generates RSA public and private keys for the client
    void send_Public_Key(const CryptoPP::RSA::PublicKey& public_key);// Sends the client's public key to the server
    bool decryptAESKey();// Decrypts the received AES key using the client's private key
    std::vector<uint8_t> encryptFile();// Encrypts the file using the decrypted AES key
    void sendFile();// Sends the encrypted file to the server
    void CRCvalid();// Informs the server that the CRC is valid
    void invalidCRCtryAgain();// Informs the server that the CRC is invalid and requests to try again
    void invalidCRCdone();// Informs the server that the CRC is invalid after reaching the maximum retry limit
    void connectToServer();// Connects the client to the server
    void disconnectFromServer();// Disconnects the client from the server

    std::array<uint8_t, 2> decimalToTwoByteArray(uint32_t decimalNumber);// Converts a decimal number to a 2-byte array

    std::array<uint8_t, 4> decimalToFourByteArray(uint32_t decimalNumber);// Converts a decimal number to a 4-byte array

    uint32_t fourByteArrayToDecimal(const std::array<uint8_t, 4>& byte_array);// Converts a 4-byte array to a decimal number

    void save_client_name(const std::string& client_name);// Saves the client name to a file named "me.info"

    void save_client_id(const std::vector<uint8_t>& data);// Appends the client ID (as a series of hexadecimal bytes) to the "me.info" file

    void save_private_key(const CryptoPP::RSA::PrivateKey& private_key_);// Appends the private key (in Base64 format) to the "me.info" file

    void read_client_name();// Reads the client name from the "me.info" file

    void read_client_id();// Reads the client ID (as a series of hexadecimal bytes) from the "me.info" file

    void read_client_private_key();// Reads the private key (in Base64 format) from the "me.info" file

    bool file_exists(const std::string& file_path);// Checks if a file exists at the given file path
   
    
    void run();// Starts the client's interaction with the server

private:
    boost::asio::io_context& io_context;
    boost::asio::ip::tcp::endpoint server_endpoint_;
    boost::asio::ip::tcp::socket socket;
    
    std::string file_path_;
    boost::array<char, 4096> buffer_;
    std::string client_name_;
    std::array<uint8_t, 255> client_name_buffer_ ;
    CryptoPP::RSA::PrivateKey private_key_;
    std::array<uint8_t, 16> client_id_;
    CryptoPP::RSA::PublicKey public_key_;
    CryptoPP::byte aes_key_[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte decrypted_aes_key_[CryptoPP::AES::DEFAULT_KEYLENGTH];
    bool is_registered_;
    std::ifstream info_file_;
    std::ofstream info_out_;
    int error_count_ = 0;
};
