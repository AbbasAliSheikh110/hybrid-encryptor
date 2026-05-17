#include "hybridencryptor.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstdio>

HybridEncryptor::HybridEncryptor() : rsaPublicKey(nullptr) {}

HybridEncryptor::~HybridEncryptor()
{
    if (rsaPublicKey)
    {
        EVP_PKEY_free(rsaPublicKey);
        rsaPublicKey = nullptr;
    }
}

bool HybridEncryptor::loadPublicKey(const std::string& pemFilePath)
{
    FILE* keyFile = fopen(pemFilePath.c_str(), "rb");
    if (!keyFile)
    {
        return false;
    }
    rsaPublicKey = PEM_read_PUBKEY(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);
    return rsaPublicKey != nullptr;
}

bool HybridEncryptor::encryptFile(const std::string& inputFilePath,
    const std::string& outputFilePath)
{
    if (!rsaPublicKey)
    {
        return false;
    }
    return encryptFileHybrid(inputFilePath, outputFilePath, rsaPublicKey);
}

bool HybridEncryptor::encryptFileHybrid(const std::string& inputFilePath,
    const std::string& outputFilePath,
    EVP_PKEY* rsaPubKey)
{
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile.is_open())
    {
        return false;
    }

    inputFile.seekg(0, std::ios::end);
    size_t fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    unsigned char* fileData = new unsigned char[fileSize];
    inputFile.read(reinterpret_cast<char*>(fileData), fileSize);
    inputFile.close();

    unsigned char aesKey[32];
    unsigned char aesIv[16];
    if (RAND_bytes(aesKey, sizeof(aesKey)) <= 0 || RAND_bytes(aesIv, sizeof(aesIv)) <= 0)
    {
        delete[] fileData;
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsaPubKey, nullptr);
    if (!ctx)
    {
        delete[] fileData;
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        delete[] fileData;
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        delete[] fileData;
        return false;
    }

    size_t encryptedKeyLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encryptedKeyLen, aesKey, sizeof(aesKey)) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        delete[] fileData;
        return false;
    }

    unsigned char* encryptedKey = new unsigned char[encryptedKeyLen];
    if (EVP_PKEY_encrypt(ctx, encryptedKey, &encryptedKeyLen, aesKey, sizeof(aesKey)) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        delete[] fileData;
        delete[] encryptedKey;
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    if (!cipherCtx)
    {
        delete[] fileData;
        delete[] encryptedKey;
        return false;
    }

    int maxEncryptedDataLen = fileSize + EVP_MAX_BLOCK_LENGTH;
    unsigned char* encryptedData = new unsigned char[maxEncryptedDataLen];
    int encryptedDataLen = 0;

    if (EVP_EncryptInit_ex(cipherCtx, EVP_aes_256_cbc(), nullptr, aesKey, aesIv) <= 0)
    {
        EVP_CIPHER_CTX_free(cipherCtx);
        delete[] fileData;
        delete[] encryptedKey;
        delete[] encryptedData;
        return false;
    }

    if (EVP_EncryptUpdate(cipherCtx, encryptedData, &encryptedDataLen, fileData, fileSize) <= 0)
    {
        EVP_CIPHER_CTX_free(cipherCtx);
        delete[] fileData;
        delete[] encryptedKey;
        delete[] encryptedData;
        return false;
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(cipherCtx, encryptedData + encryptedDataLen, &finalLen) <= 0)
    {
        EVP_CIPHER_CTX_free(cipherCtx);
        delete[] fileData;
        delete[] encryptedKey;
        delete[] encryptedData;
        return false;
    }

    encryptedDataLen += finalLen;
    EVP_CIPHER_CTX_free(cipherCtx);

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile.is_open())
    {
        delete[] fileData;
        delete[] encryptedKey;
        delete[] encryptedData;
        return false;
    }

    uint32_t keyLenWrite = static_cast<uint32_t>(encryptedKeyLen);
    outputFile.write(reinterpret_cast<char*>(&keyLenWrite), sizeof(keyLenWrite));
    outputFile.write(reinterpret_cast<char*>(encryptedKey), encryptedKeyLen);
    outputFile.write(reinterpret_cast<char*>(aesIv), sizeof(aesIv));
    outputFile.write(reinterpret_cast<char*>(encryptedData), encryptedDataLen);
    outputFile.close();

    delete[] fileData;
    delete[] encryptedKey;
    delete[] encryptedData;

    return true;
}