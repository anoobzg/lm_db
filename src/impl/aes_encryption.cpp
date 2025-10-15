#include "lm/crypto/aes_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <fstream>
#include <stdexcept>
#include <cstring>

namespace lm {
namespace crypto {

AESEncryption::AESEncryption(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("Key must be 32 bytes for AES-256");
    }
    key_ = key;
}

std::vector<uint8_t> AESEncryption::generateKeyFromPassword(const std::string& password) {
    std::vector<uint8_t> key(32);
    
    // Use SHA-256 hash password to generate key
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(key.data(), &sha256);
    
    return key;
}

std::vector<uint8_t> AESEncryption::generateRandomKey() {
    std::vector<uint8_t> key(32);
    
    if (RAND_bytes(key.data(), 32) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    
    return key;
}

std::vector<uint8_t> AESEncryption::encrypt(const std::vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Generate random IV
    std::vector<uint8_t> iv = generateIV();
    
    // Initialize encryption context
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    // Calculate output buffer size
    int len;
    int ciphertext_len;
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    
    // Execute encryption
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;
    
    // Complete encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Adjust output size
    ciphertext.resize(ciphertext_len);
    
    // Add IV to the front of ciphertext
    std::vector<uint8_t> result;
    result.reserve(iv.size() + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    return result;
}

std::vector<uint8_t> AESEncryption::decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() < 16) {
        throw std::invalid_argument("Ciphertext too short");
    }
    
    // Extract IV from the front
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 16);
    std::vector<uint8_t> actualCiphertext(ciphertext.begin() + 16, ciphertext.end());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize decryption context
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    // Calculate output buffer size
    int len;
    int plaintext_len;
    std::vector<uint8_t> plaintext(actualCiphertext.size() + 16);
    
    // Execute decryption
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actualCiphertext.data(), actualCiphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;
    
    // Complete decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Adjust output size
    plaintext.resize(plaintext_len);
    
    return plaintext;
}

std::string AESEncryption::encryptString(const std::string& plaintext) {
    std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertext = encrypt(plaintextBytes);
    return base64Encode(ciphertext);
}

std::string AESEncryption::decryptString(const std::string& ciphertext) {
    std::vector<uint8_t> ciphertextBytes = base64Decode(ciphertext);
    std::vector<uint8_t> plaintext = decrypt(ciphertextBytes);
    return std::string(plaintext.begin(), plaintext.end());
}

bool AESEncryption::encryptFile(const std::string& inputPath, const std::string& outputPath) {
    try {
        std::ifstream inputFile(inputPath, std::ios::binary);
        if (!inputFile) {
            return false;
        }
        
        std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(inputFile)),
                                      std::istreambuf_iterator<char>());
        inputFile.close();
        
        std::vector<uint8_t> ciphertext = encrypt(plaintext);
        
        std::ofstream outputFile(outputPath, std::ios::binary);
        if (!outputFile) {
            return false;
        }
        
        outputFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        outputFile.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

bool AESEncryption::decryptFile(const std::string& inputPath, const std::string& outputPath) {
    try {
        std::ifstream inputFile(inputPath, std::ios::binary);
        if (!inputFile) {
            return false;
        }
        
        std::vector<uint8_t> ciphertext((std::istreambuf_iterator<char>(inputFile)),
                                       std::istreambuf_iterator<char>());
        inputFile.close();
        
        std::vector<uint8_t> plaintext = decrypt(ciphertext);
        
        std::ofstream outputFile(outputPath, std::ios::binary);
        if (!outputFile) {
            return false;
        }
        
        outputFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        outputFile.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

std::string AESEncryption::base64Encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> AESEncryption::base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> result(encoded.length());
    int decodedLength = BIO_read(bio, result.data(), encoded.length());
    
    BIO_free_all(bio);
    
    result.resize(decodedLength);
    return result;
}

std::vector<uint8_t> AESEncryption::generateIV() {
    std::vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), 16) != 1) {
        throw std::runtime_error("Failed to generate random IV");
    }
    return iv;
}

} // namespace crypto
} // namespace lm
