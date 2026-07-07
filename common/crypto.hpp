#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>


static const int AES_KEY_LEN  = 32;  
static const int AES_IV_LEN   = 12;  
static const int AES_TAG_LEN  = 16;  

class Crypto {
public:
    
    explicit Crypto(const std::string& key_str) {
        
        std::memset(key_, 0, AES_KEY_LEN);
        
        size_t copy_len = std::min(key_str.size(), (size_t)AES_KEY_LEN);
        std::memcpy(key_, key_str.data(), copy_len);
    }

    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        
        uint8_t iv[AES_IV_LEN];
        if (RAND_bytes(iv, AES_IV_LEN) != 1) {
            throw std::runtime_error("Failed to generate random IV");
        }

        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt init failed");
        }

        
        std::vector<uint8_t> ciphertext(plaintext.size());
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx,
                              ciphertext.data(), &out_len,
                              plaintext.data(),  (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt update failed");
        }

        
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt final failed");
        }
        ciphertext.resize(out_len + final_len);

        
        uint8_t tag[AES_TAG_LEN];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag);

        EVP_CIPHER_CTX_free(ctx);

        
        std::vector<uint8_t> result;
        result.reserve(AES_IV_LEN + AES_TAG_LEN + ciphertext.size());
        result.insert(result.end(), iv,          iv + AES_IV_LEN);
        result.insert(result.end(), tag,         tag + AES_TAG_LEN);
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        return result;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
       
        if (data.size() < (size_t)(AES_IV_LEN + AES_TAG_LEN)) {
            throw std::runtime_error("Encrypted data too short");
        }

        const uint8_t* iv         = data.data();
        const uint8_t* tag        = data.data() + AES_IV_LEN;
        const uint8_t* ciphertext = data.data() + AES_IV_LEN + AES_TAG_LEN;
        size_t cipher_len         = data.size() - AES_IV_LEN - AES_TAG_LEN;


        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decrypt init failed");
        }

        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN,
                            const_cast<uint8_t*>(tag));

        
        std::vector<uint8_t> plaintext(cipher_len);
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx,
                              plaintext.data(), &out_len,
                              ciphertext,       (int)cipher_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decrypt update failed");
        }

        int final_len = 0;
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret != 1) {
            throw std::runtime_error("Decryption FAILED — data may be tampered!");
        }

        plaintext.resize(out_len + final_len);
        return plaintext;
    }

private:
    uint8_t key_[AES_KEY_LEN];  
};