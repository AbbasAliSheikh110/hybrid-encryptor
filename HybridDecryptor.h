#ifndef HYBRIDDECRYPTOR_H
#define HYBRIDDECRYPTOR_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>

class HybridDecryptor
{
public:
    HybridDecryptor();
    ~HybridDecryptor();

    bool loadPrivateKey(const std::string& pemFilePath);
    bool decryptFile(const std::string& inputFilePath,
        const std::string& outputFilePath);

private:
    EVP_PKEY* rsaPrivateKey = nullptr;

    bool decryptFileHybrid(const std::string& inputFilePath,
        const std::string& outputFilePath,
        EVP_PKEY* rsaPrivKey);
};

#endif#pragma once
