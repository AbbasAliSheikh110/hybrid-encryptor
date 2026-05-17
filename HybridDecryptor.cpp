#include "HybridDecryptor.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstdint>

HybridDecryptor::HybridDecryptor() = default;

HybridDecryptor::~HybridDecryptor()
{
    if (rsaPrivateKey) {
        EVP_PKEY_free(rsaPrivateKey);
    }
}

bool HybridDecryptor::loadPrivateKey(const std::string& pemFilePath)
{
    FILE* fp = fopen(pemFilePath.c_str(), "rb");
    if (!fp) {
        std::cerr << "FAIL: cannot open private_key.pem" << std::endl;
        return false;
    }
    rsaPrivateKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsaPrivateKey) {
        std::cerr << "FAIL: PEM_read_PrivateKey failed" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    std::cerr << "OK: private key loaded" << std::endl;
    return true;
}

bool HybridDecryptor::decryptFile(const std::string& inputFilePath,
    const std::string& outputFilePath)
{
    if (!rsaPrivateKey) return false;
    return decryptFileHybrid(inputFilePath, outputFilePath, rsaPrivateKey);
}

bool HybridDecryptor::decryptFileHybrid(const std::string& inputFilePath,
    const std::string& outputFilePath,
    EVP_PKEY* rsaPrivKey)
{
    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "FAIL: cannot open input file" << std::endl;
        return false;
    }

    uint32_t keySize = 0;
    inFile.read(reinterpret_cast<char*>(&keySize), sizeof(keySize));
    std::cerr << "KEY SIZE READ: " << keySize << std::endl;

    if (keySize == 0 || keySize > 10000) {
        std::cerr << "FAIL: invalid key size" << std::endl;
        return false;
    }

    std::vector<unsigned char> encryptedAesKey(keySize);
    inFile.read(reinterpret_cast<char*>(encryptedAesKey.data()), keySize);

    unsigned char aesIv[16];
    inFile.read(reinterpret_cast<char*>(aesIv), sizeof(aesIv));
    std::cerr << "OK: read key and IV" << std::endl;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsaPrivKey, NULL);
    if (!ctx) {
        std::cerr << "FAIL: EVP_PKEY_CTX_new" << std::endl;
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "FAIL: EVP_PKEY_decrypt_init" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "FAIL: set_rsa_padding" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t aesKeyLen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &aesKeyLen,
        encryptedAesKey.data(), encryptedAesKey.size()) <= 0) {
        std::cerr << "FAIL: EVP_PKEY_decrypt get length" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> aesKey(aesKeyLen);
    if (EVP_PKEY_decrypt(ctx, aesKey.data(), &aesKeyLen,
        encryptedAesKey.data(), encryptedAesKey.size()) <= 0) {
        std::cerr << "FAIL: EVP_PKEY_decrypt actual" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    std::cerr << "OK: RSA decrypt success, AES key len=" << aesKeyLen << std::endl;
    EVP_PKEY_CTX_free(ctx);

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cipherCtx, EVP_aes_256_cbc(), NULL,
        aesKey.data(), aesIv);

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "FAIL: cannot open output file" << std::endl;
        EVP_CIPHER_CTX_free(cipherCtx);
        return false;
    }

    const int CHUNK_SIZE = 4096;
    unsigned char inBuffer[CHUNK_SIZE];
    unsigned char outBuffer[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    while (inFile.read(reinterpret_cast<char*>(inBuffer), CHUNK_SIZE)
        || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        EVP_DecryptUpdate(cipherCtx, outBuffer, &outLen, inBuffer, bytesRead);
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    }

    if (EVP_DecryptFinal_ex(cipherCtx, outBuffer, &outLen) <= 0) {
        std::cerr << "FAIL: EVP_DecryptFinal_ex" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipherCtx);
        return false;
    }

    std::cerr << "OK: AES decrypt success" << std::endl;
    outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    EVP_CIPHER_CTX_free(cipherCtx);
    inFile.close();
    outFile.close();
    return true;
}