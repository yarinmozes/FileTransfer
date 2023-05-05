//yarin mozes
//client.cpp
#include "client.h"

// Constructor for the Client class
Client::Client(boost::asio::io_context& io_context, const std::string& ip, int port, const std::string& client_name, const std::string& file_path)
    : io_context(io_context), server_endpoint_(boost::asio::ip::address::from_string(ip), port), socket(io_context), client_name_(client_name), file_path_(file_path),
    is_registered_(false), error_count_(0) {
}

// Main function that runs the client
void Client::run() {
    
    // Try connecting to the server
    try {
        connectToServer();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: Failed to connect to the server: " << e.what() << "\n";
        return;
    }
    // If the "me.info" is exist, try to reconnect to server
    if (file_exists("me.info")) {
        read_client_name();
        read_client_id();
        try {
            read_client_private_key();
        }
        catch (const std::exception& e) {
            std::cerr << "Error reading the private key, please check the me.info file: " << e.what() << "\n";
            return;
        }
        reconnectClient();
    }
    else {
        //If the "me.info" file does not exist, trying to register
        registerClient();
    }

    disconnectFromServer();
}

// Reads data from the socket into the buffer_ and returns it as a string.
std::string Client::read()
{
    boost::system::error_code error;
    size_t len = socket.read_some(boost::asio::buffer(buffer_), error);
    if (error == boost::asio::error::eof)
        return "";
    else if (error)
        throw boost::system::system_error(error);
    return std::string(buffer_.begin(), buffer_.begin() + len);
}

// Reads n bytes of data from the socket into the buffer_ and returns it as a string.
std::string Client::read(std::size_t n)
{
    boost::system::error_code error;
    boost::asio::read(socket, boost::asio::buffer(buffer_, n), error);
    if (error == boost::asio::error::eof)
        return "";
    else if (error)
        throw boost::system::system_error(error);
    return std::string(buffer_.begin(), buffer_.begin() + n);
}

// Registers the client with the server by sending a registration request.
void Client::registerClient() {
    // Prepare the header
    Request reg_req;
    std::memset(reg_req.cid.data(), 0, reg_req.cid.size());
    reg_req.request_code = decimalToTwoByteArray(1100);
    reg_req.payload_size = static_cast<uint32_t>(client_name_.size() + 1); // Include null terminator
    uint32_t total_size = sizeof(reg_req.cid) + sizeof(reg_req.version) + sizeof(reg_req.request_code) + sizeof(reg_req.payload_size) + reg_req.payload_size;

    std::cerr << "The size of the registration request is: " << total_size << "\n";
    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(client_name_.size() + 1);

    // Fill in the payload
    std::vector<uint8_t> payload(client_name_.begin(), client_name_.end());
    payload.push_back('\0');

    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), reg_req.cid.data(), sizeof(reg_req.cid));
    std::memcpy(request.data() + sizeof(reg_req.cid), &reg_req.version, sizeof(reg_req.version));
    std::memcpy(request.data() + sizeof(reg_req.cid) + sizeof(reg_req.version), reg_req.request_code.data(), sizeof(reg_req.request_code));
    std::memcpy(request.data() + sizeof(reg_req.cid) + sizeof(reg_req.version) + sizeof(reg_req.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(reg_req.cid) + sizeof(reg_req.version) + sizeof(reg_req.request_code) + sizeof(payload_size_arr), payload.data(), payload.size());

    std::cerr << "The registration request is: ";
    for (const auto& byte : request) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cerr << "\n";

    sendRequest(request);

    try {
        Response response = receiveResponse();
        printServerResponse(response);
        if (response.response_code == 2100) {
            try {
                save_client_name(client_name_);
                save_client_id(response.payload);
                generateRSAKeys();
            }
            catch (...) {
                std::cout << "An error occurred while saving the client information in the me.info file\n";
                return;
            }
            

        }
        else if (response.response_code == 2101){
            std::cout << "The client is already registered on the server, trying to reconnect\n";
            reconnectClient();
        }
        else {
            std::cout << "The client failed to connect to the server\n";
            return;
        }
       
        
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Error: Failed to receive response from the server: " << e.what() << "\n";
        return;
    }
}
  
// Attempts to reconnect the client to the server by sending a reconnect request.
void Client::reconnectClient() {
    // Prepare the header
    Request recon_req;
    recon_req.cid = client_id_;
    recon_req.request_code = decimalToTwoByteArray(1102);
    recon_req.payload_size = static_cast<uint32_t>(client_name_.size() + 1); // Include null terminator
    uint32_t total_size = sizeof(recon_req.cid) + sizeof(recon_req.version) + sizeof(recon_req.request_code) + sizeof(recon_req.payload_size) + recon_req.payload_size;

    std::cerr << "The size of the reconnect request is: " << total_size << "\n";
    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(client_name_.size() + 1);

    // Fill in the payload
    std::vector<uint8_t> payload(client_name_.begin(), client_name_.end());
    payload.push_back('\0');
    recon_req.payload = payload;
    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), recon_req.cid.data(), sizeof(recon_req.cid));
    std::memcpy(request.data() + sizeof(recon_req.cid), &recon_req.version, sizeof(recon_req.version));
    std::memcpy(request.data() + sizeof(recon_req.cid) + sizeof(recon_req.version), recon_req.request_code.data(), sizeof(recon_req.request_code));
    std::memcpy(request.data() + sizeof(recon_req.cid) + sizeof(recon_req.version) + sizeof(recon_req.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(recon_req.cid) + sizeof(recon_req.version) + sizeof(recon_req.request_code) + sizeof(payload_size_arr), payload.data(), payload.size());

    std::cerr << "The reconnect request is: ";
    for (const auto& byte : request) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cerr << "\n";

    sendRequest(request);

    try {
        Response response = receiveResponse();
        printServerResponse(response);
        if (response.response_code == 2105) {
         
            std::memcpy(client_id_.data(), response.payload.data(), client_id_.size());
            std::memcpy(aes_key_, response.payload.data() + client_id_.size(), sizeof(aes_key_));

            std::cerr << "The server confirmed that the client successfully reconnected";

            if (decryptAESKey()) {
                sendFile();
            }
            else {
                std::cerr << "Error: Decrypt the AES key by the private key failed";
                return;
            }
        }
        else {
            std::cerr << "The request to reconnect failed, trying to register";
            registerClient();
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Error: Failed to receive response from the server: " << e.what() << "\n";
        return;
    }
}

// Generates a 1024-bit RSA key pair (private and public keys) for the client,
void Client::generateRSAKeys() {
    // Set up a random number generator
    CryptoPP::AutoSeededRandomPool rng;

    // Generate a 1024-bit RSA key pair
    CryptoPP::InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024);

    // Create the private and public keys from the parameters
    private_key_ = CryptoPP::RSA::PrivateKey(parameters);
    public_key_ = CryptoPP::RSA::PublicKey(parameters);

    // Save the private key to a file
    save_private_key(private_key_);
    send_Public_Key(public_key_);
}

// Serializes and sends the provided RSA public key to the server.
void Client::send_Public_Key(const CryptoPP::RSA::PublicKey& public_key) {
    /// Serialize the public key
    CryptoPP::ByteQueue queue;
    public_key.Save(queue);

    // Get the size of the serialized public key
    size_t public_key_size = queue.CurrentSize();

    // Prepare the header
    Request public_key_req;
    public_key_req.cid = client_id_;
    public_key_req.request_code = decimalToTwoByteArray(1101);
    public_key_req.payload_size = static_cast<uint32_t>(public_key_size + client_name_buffer_.size());
    uint32_t total_size = sizeof(public_key_req.cid) + sizeof(public_key_req.version) + sizeof(public_key_req.request_code) + sizeof(public_key_req.payload_size) + public_key_req.payload_size;

    // Create a 255-byte ASCII string buffer for the client_name_
    std::copy(client_name_.begin(), client_name_.end(), client_name_buffer_.begin());

    // Read the serialized public key into a vector
    std::vector<uint8_t> vec_key(public_key_size);
    queue.Get(vec_key.data(), vec_key.size());

    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), public_key_req.cid.data(), sizeof(public_key_req.cid));
    std::memcpy(request.data() + sizeof(public_key_req.cid), &public_key_req.version, sizeof(public_key_req.version));
    std::memcpy(request.data() + sizeof(public_key_req.cid) + sizeof(public_key_req.version), public_key_req.request_code.data(), sizeof(public_key_req.request_code));
    std::memcpy(request.data() + sizeof(public_key_req.cid) + sizeof(public_key_req.version) + sizeof(public_key_req.request_code), &public_key_req.payload_size, sizeof(public_key_req.payload_size));
    std::memcpy(request.data() + sizeof(public_key_req.cid) + sizeof(public_key_req.version) + sizeof(public_key_req.request_code) + sizeof(public_key_req.payload_size), client_name_buffer_.data(), client_name_buffer_.size());
    std::memcpy(request.data() + sizeof(public_key_req.cid) + sizeof(public_key_req.version) + sizeof(public_key_req.request_code) + sizeof(public_key_req.payload_size) + client_name_buffer_.size(), vec_key.data(), vec_key.size());


    // Send the request
    sendRequest(request);

    // Receive the response
    try {
        Response response = receiveResponse();
        printServerResponse(response);
        if (response.response_code == 2102) {
            std::cout << "The public key has been successfully sent to the server" << std::endl;
            std::memcpy(client_id_.data(), response.payload.data(), client_id_.size());
            size_t client_id_length = client_id_.size();

            std::memcpy(aes_key_, response.payload.data() + client_id_length, sizeof(aes_key_));
            if (decryptAESKey()) {
                sendFile();
            }
            else {
                std::cerr << "Error: Decrypt the AES key by the private key failed";
                return;
            }

        }
        else {
            std::cerr << "Error: Failed to send the public key to the server" << std::endl;
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Error: Failed to receive response from the server: " << e.what() << "\n";
    }
}

/// Sends a request to the server 
void Client::sendRequest(const std::vector<uint8_t>& request) {
    boost::asio::write(socket, boost::asio::buffer(request));
}

//function to receives response from the server.
Response Client::receiveResponse() {
    boost::asio::ip::tcp::socket& socket = this->socket;

    // Read the header of the response (server_version, response_code, payload_size)
    std::array<uint8_t, 7> header_data;
    boost::asio::read(socket, boost::asio::buffer(header_data));

    // Extract the header fields (assuming little-endian)
    uint8_t server_version = header_data[0];
    uint16_t response_code = header_data[1] | (header_data[2] << 8);
    uint32_t payload_size = header_data[3] | (header_data[4] << 8) | (header_data[5] << 16) | (header_data[6] << 24);

    // Read the payload based on payload_size
    std::vector<uint8_t> payload(payload_size);
    boost::asio::read(socket, boost::asio::buffer(payload));

    // Create and return the Response object
    return Response(response_code, payload);
}

//function that prints the server response to the console.
void Client::printServerResponse(const Response& response) {
    std::cout << "Server Version: " << static_cast<int>(response.server_version) << std::endl;
    std::cout << "Response Code: " << response.response_code << std::endl;
    std::cout << "Payload Size: " << response.payload_size << std::endl;
    std::cout << "Payload Data: ";
    for (const auto& byte : response.payload) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
}

//function that returns a boolean indicating if the decryption was successful or not.
bool Client::decryptAESKey() {
    try {

        // First, encrypt the AES key using the RSA private key
        std::string encrypted_aes_key;
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(private_key_);

        CryptoPP::StringSource ss1(
            std::string(reinterpret_cast<char*>(aes_key_), CryptoPP::AES::DEFAULT_KEYLENGTH),
            true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(encrypted_aes_key))
        );

        // Now, decrypt the encrypted AES key to unlock it
        std::string decrypted_aes_key;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key_);

        CryptoPP::StringSource ss2(
            encrypted_aes_key,
            true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decrypted_aes_key))
        );

        // Copy the decrypted AES key back to the original aes_key_
        memcpy(decrypted_aes_key_, decrypted_aes_key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
        std::cerr << "The AES key was unlock successfully " << std::endl;
        return true;
    }
    catch (CryptoPP::Exception& e) {
        std::cerr << "Error unlocking AES key: " << e.what() << std::endl;
        return false;
    }
}

// Function that encrypts the file data using the AES key and returns a vector of encrypted data.
std::vector<uint8_t> Client::encryptFile() {
    // Check if the file exists
    std::ifstream file(file_path_, std::ios::binary);
    if (!file) {
        throw std::runtime_error("File not found: " + file_path_);
    }
    // Read the file contents
    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Generate a random IV
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, sizeof(iv));

    // Encrypt the file data using the AES key
    std::vector<uint8_t> encrypted_data;
    try {
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(decrypted_aes_key_, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

        CryptoPP::StreamTransformationFilter stf(encryption, new CryptoPP::VectorSink(encrypted_data));
        stf.Put(file_data.data(), file_data.size());
        stf.MessageEnd();
    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Error encrypting file: " + std::string(e.what()));
    }

    // Prepend the IV to the encrypted data
    encrypted_data.insert(encrypted_data.begin(), iv, iv + sizeof(iv));

    return encrypted_data;
    
}

//function to verify the CRC of the encrypted file data and compares it to the received CRC.
bool verify_crc(const std::vector<uint8_t>& encrypted_file_data, uint32_t received_crc) {
    boost::crc_32_type crc_calculator;
    crc_calculator.process_bytes(encrypted_file_data.data(), encrypted_file_data.size());
    uint32_t calculated_crc = crc_calculator.checksum();

    return calculated_crc == received_crc;
}

//function to sends the encrypted file to the server and handles the server's response.
void Client::sendFile() {
    // Read the file contents
    std::ifstream file(file_path_, std::ios::binary);
    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Encrypt the file_data
    std::vector<uint8_t> encrypted_file_data = encryptFile();

    // Prepare the request
    Request req_send_file;
    req_send_file.cid = client_id_;
    req_send_file.request_code = decimalToTwoByteArray(1103);

    uint32_t encrypted_file_size = static_cast<uint32_t>(encrypted_file_data.size());
    std::array<uint8_t, 4> file_size_bytes = decimalToFourByteArray(encrypted_file_size);

    std::vector<uint8_t> file_name_bytes(file_path_.begin(), file_path_.end());
    file_name_bytes.push_back('\0');
    // Construct the payload
    req_send_file.payload.resize(4 + 255 + encrypted_file_data.size());
    std::memcpy(req_send_file.payload.data(), file_size_bytes.data(), file_name_bytes.size());
    std::memcpy(req_send_file.payload.data() + 4, file_name_bytes.data(), 255);
    std::memcpy(req_send_file.payload.data() + 4 + 255, encrypted_file_data.data(), encrypted_file_data.size());

    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(req_send_file.payload.size());
    uint32_t total_size = sizeof(req_send_file.cid) + sizeof(req_send_file.version) + sizeof(req_send_file.request_code) + sizeof(req_send_file.payload_size) + req_send_file.payload_size;
    std::cerr << "The size of the request to send a file is: " << total_size << "\n";

    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), req_send_file.cid.data(), sizeof(req_send_file.cid));
    std::memcpy(request.data() + sizeof(req_send_file.cid), &req_send_file.version, sizeof(req_send_file.version));
    std::memcpy(request.data() + sizeof(req_send_file.cid) + sizeof(req_send_file.version), req_send_file.request_code.data(), sizeof(req_send_file.request_code));
    std::memcpy(request.data() + sizeof(req_send_file.cid) + sizeof(req_send_file.version) + sizeof(req_send_file.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(req_send_file.cid) + sizeof(req_send_file.version) + sizeof(req_send_file.request_code) + sizeof(payload_size_arr), req_send_file.payload.data(), req_send_file.payload.size());

    // Send the request to the server
    sendRequest(request);

    // Wait for the server's response
    Response response = receiveResponse();
    printServerResponse(response);
    // Check if the response is valid
    if (response.response_code == 2103  ) {
        uint32_t received_crc = *reinterpret_cast<const uint32_t*>(response.payload.data() + 16 + 4 + 255);
        if (verify_crc(encrypted_file_data, received_crc)) {
            std::cout << "File sent successfully and CRC matches." << std::endl;
            CRCvalid();
        }
        else if(error_count_< 3){
            std::cerr << "File sent successfully, but CRC does not match." << std::endl;
            error_count_++;
            std::cerr << "Sending a request to the server that the CRC is incorrect" << std::endl;
            invalidCRCtryAgain();
        }
        else {
            std::cerr << "File sent successfully, but CRC does not match for the fourth time." << std::endl;
            error_count_++;
            std::cerr << "Finishing trying to send the file" << std::endl;
            invalidCRCdone();
        }
    }
    else {
        std::cerr << "Error sending file to the server." << std::endl;
        disconnectFromServer();
    }
}

//functiom to sends a CRC valid request to the server, indicating that the file transfer was successful.
void Client::CRCvalid() {
    Request valid_crc_req;
    valid_crc_req.cid = client_id_;
    valid_crc_req.request_code = decimalToTwoByteArray(1104);
    valid_crc_req.payload_size = static_cast<uint32_t>(file_path_.size() + 1); // Include null terminator
    uint32_t total_size = sizeof(valid_crc_req.cid) + sizeof(valid_crc_req.version) + sizeof(valid_crc_req.request_code) + sizeof(valid_crc_req.payload_size) + valid_crc_req.payload_size;

    std::cerr << "The size of the CRC valid request is: " << total_size << "\n";
    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(file_path_.size() + 1);

    // Fill in the payload
    std::vector<uint8_t> payload(file_path_.begin(), file_path_.end());
    payload.push_back('\0');
    valid_crc_req.payload = payload;
    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), valid_crc_req.cid.data(), sizeof(valid_crc_req.cid));
    std::memcpy(request.data() + sizeof(valid_crc_req.cid), &valid_crc_req.version, sizeof(valid_crc_req.version));
    std::memcpy(request.data() + sizeof(valid_crc_req.cid) + sizeof(valid_crc_req.version), valid_crc_req.request_code.data(), sizeof(valid_crc_req.request_code));
    std::memcpy(request.data() + sizeof(valid_crc_req.cid) + sizeof(valid_crc_req.version) + sizeof(valid_crc_req.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(valid_crc_req.cid) + sizeof(valid_crc_req.version) + sizeof(valid_crc_req.request_code) + sizeof(payload_size_arr), payload.data(), payload.size());

    

    sendRequest(request);

    try {
        Response response = receiveResponse();
        printServerResponse(response);
        if (response.response_code == 2104) {

            std::cerr << "The server confirmed receipt of the file, the file transfer was completed successfully. Thank you for saving the file on our servers";
            return;
            
        }
        else {
            std::cerr << "The server sent an unexpected response";
            return;
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Error: Failed to receive response from the server: " << e.what() << "\n";
        return;
        
    }

}

//functiom to send request crc invalid to the sever
void Client::invalidCRCtryAgain()
{
    Request invalid_crc_req;
    invalid_crc_req.cid = client_id_;
    invalid_crc_req.request_code = decimalToTwoByteArray(1105);
    invalid_crc_req.payload_size = static_cast<uint32_t>(file_path_.size() + 1); // Include null terminator
    uint32_t total_size = sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code) + sizeof(invalid_crc_req.payload_size) + invalid_crc_req.payload_size;

    std::cerr << "The size of the CRC invalid request is: " << total_size << "\n";
    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(file_path_.size() + 1);

    // Fill in the payload
    std::vector<uint8_t> payload(file_path_.begin(), file_path_.end());
    payload.push_back('\0');
    invalid_crc_req.payload = payload;
    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), invalid_crc_req.cid.data(), sizeof(invalid_crc_req.cid));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid), &invalid_crc_req.version, sizeof(invalid_crc_req.version));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version), invalid_crc_req.request_code.data(), sizeof(invalid_crc_req.request_code));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code) + sizeof(payload_size_arr), payload.data(), payload.size());

    sendRequest(request);
    sendFile();
}

//functiom to sends a CRC invalid and done request to the server, 
//indicating that the CRC does not match for the fourth time and the file transfer is considered unsuccessful.
void Client::invalidCRCdone() {
    Request invalid_crc_req;
    invalid_crc_req.cid = client_id_;
    invalid_crc_req.request_code = decimalToTwoByteArray(1106);
    invalid_crc_req.payload_size = static_cast<uint32_t>(file_path_.size() + 1); // Include null terminator
    uint32_t total_size = sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code) + sizeof(invalid_crc_req.payload_size) + invalid_crc_req.payload_size;

    std::cerr << "The size of the CRC invalid ,done  request is: " << total_size << "\n";
    std::array<uint8_t, 4> payload_size_arr = decimalToFourByteArray(file_path_.size() + 1);

    // Fill in the payload
    std::vector<uint8_t> payload(file_path_.begin(), file_path_.end());
    payload.push_back('\0');
    invalid_crc_req.payload = payload;
    // Construct the request
    std::vector<uint8_t> request(total_size);
    std::memcpy(request.data(), invalid_crc_req.cid.data(), sizeof(invalid_crc_req.cid));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid), &invalid_crc_req.version, sizeof(invalid_crc_req.version));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version), invalid_crc_req.request_code.data(), sizeof(invalid_crc_req.request_code));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code), payload_size_arr.data(), sizeof(payload_size_arr));
    std::memcpy(request.data() + sizeof(invalid_crc_req.cid) + sizeof(invalid_crc_req.version) + sizeof(invalid_crc_req.request_code) + sizeof(payload_size_arr), payload.data(), payload.size());



    sendRequest(request);

    try {
        Response response = receiveResponse();
        printServerResponse(response);
        if (response.response_code == 2104) {

            std::cerr << "The CRC was incorrect for the fourth time, the file was not saved on the server because it failed to verify the CRC. Done";
            return;

        }
        else {
            std::cerr << "The server sent an unexpected response";
            return;
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Error: Failed to receive response from the server: " << e.what() << "\n";
        return;

    }
}

//function to connect the server
void Client::connectToServer() {
    try {
        socket.connect(server_endpoint_);
    }
    catch (boost::system::system_error& e) {
        // Handle the error (e.g., print an error message or throw an exception)
        std::cerr << "Error: Failed to connect to the server: " << e.what() << "\n";
        throw e;
    }
}

//function to discinnect from the server
void Client::disconnectFromServer() {
    socket.close();
}

// Converts a decimal value to a two-byte array and returns it.
std::array<uint8_t, 2> Client::decimalToTwoByteArray(uint32_t decimalNumber) {
    std::array<uint8_t, 2> byteArray = {};
    byteArray[0] = decimalNumber & 0xFF; // get the least significant byte
    byteArray[1] = (decimalNumber >> 8) & 0xFF; // get the most significant byte
    return byteArray;
}

// Converts a decimal number to a 4-byte array
std::array<uint8_t, 4> Client::decimalToFourByteArray(uint32_t decimalNumber) {
    std::array<uint8_t, 4> byteArray = {};
    byteArray[0] = decimalNumber & 0xFF; // get the least significant byte
    byteArray[1] = (decimalNumber >> 8) & 0xFF; // get the second least significant byte
    byteArray[2] = (decimalNumber >> 16) & 0xFF; // get the second most significant byte
    byteArray[3] = (decimalNumber >> 24) & 0xFF; // get the most significant byte
    return byteArray;
}

// Converts a 4-byte array to a decimal number
uint32_t Client::fourByteArrayToDecimal(const std::array<uint8_t, 4>& byte_array) {
    uint32_t decimal = 0;
    decimal |= byte_array[0] << 24;
    decimal |= byte_array[1] << 16;
    decimal |= byte_array[2] << 8;
    decimal |= byte_array[3];
    return decimal;
}

// Saves the client name to a file named "me.info"
void Client:: save_client_name(const std::string& client_name) {
    std::ofstream file("me.info", std::ios::out | std::ios::trunc);
    if (file.is_open()) {
        file << client_name << std::endl;
        file.close();
    }
    else {
        std::cerr << "Error opening file 'me.info' for writing" << std::endl;
    }
}

// Saves the client ID (as a series of hexadecimal bytes) to the "me.info" file
void Client::save_client_id(const std::vector<uint8_t>& data) {
    std::ofstream file("me.info", std::ios::out | std::ios::app);
    if (file.is_open()) {
        for (const auto& byte : data) {
            file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        file << std::endl;
        file.close();
    }
    else {
        std::cerr << "Error opening file 'me.info' for writing" << std::endl;
    }
}

//  Saves the private key (in Base64 format) to the "me.info" file
void Client::save_private_key(const CryptoPP::RSA::PrivateKey& private_key_) {
    std::ofstream file("me.info", std::ios::out | std::ios::app);
    if (file.is_open()) {
        CryptoPP::ByteQueue privateKeyQueue;
        private_key_.Save(privateKeyQueue);
        CryptoPP::Base64Encoder base64Encoder(new CryptoPP::FileSink(file), false);
        privateKeyQueue.CopyTo(base64Encoder);
        base64Encoder.MessageEnd();

        file << std::endl;
        file.close();
    }
    else {
        std::cerr << "Error opening file 'me.info' for writing" << std::endl;
    }
}

// Reads the client name from the "me.info" file
void Client::read_client_name() {
    std::ifstream file("me.info");
    std::getline(file, client_name_);
    file.close();
}

// Reads the client ID (as a series of hexadecimal bytes) from the "me.info" file
void Client::read_client_id() {
    std::ifstream file("me.info");
    std::string line;
    std::getline(file, line);
    std::getline(file, line);
    for (size_t i = 0; i < client_id_.size(); i++) {
        std::string hex_byte = line.substr(i * 2, 2);
        client_id_[i] = std::stoi(hex_byte, nullptr, 16);
    }
    file.close();
}

// Reads the private key (in Base64 format) from the "me.info" file
void Client::read_client_private_key() {
    std::ifstream file("me.info");
    std::string line;
    std::getline(file, line);
    std::getline(file, line);
    std::getline(file, line);
    CryptoPP::ByteQueue queue;
    CryptoPP::StringSource string_source(line, true, new CryptoPP::Base64Decoder);
    string_source.TransferTo(queue);
    queue.MessageEnd();
    private_key_.Load(queue);
    file.close();
}

// Checks if a file exists at the given file path
bool Client:: file_exists(const std::string& file_path) {
    std::ifstream file(file_path);
    bool exists = file.good();
    file.close();
    return exists;
}

int main() {
    
    std::string ip, client_name, file_path;
    int port;

    // Read the transfer.info file and get the required information
    std::ifstream info_file("transfer.info");
    if (info_file.is_open()) {
        std::string ipAddressAndPort;
        std::getline(info_file, ipAddressAndPort);
        size_t colonPos = ipAddressAndPort.find(':');
        ip = ipAddressAndPort.substr(0, colonPos);
        port = std::stoi(ipAddressAndPort.substr(colonPos + 1));

        // Read the client name from the second line
        std::getline(info_file, client_name);

        // Read the file path from the third line
        std::getline(info_file, file_path);
        info_file.close();
    }
    else {
        std::cerr << "Error: Failed to open transfer.info file\n";
        return 1;
    }

    // Create an io_context object
    boost::asio::io_context io_context;

    Client client(io_context, ip, port, client_name, file_path);
    client.run();

    // Clean up
    client.disconnectFromServer();
    
    return 0;
}
