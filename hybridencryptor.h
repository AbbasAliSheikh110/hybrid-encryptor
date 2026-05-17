#ifndef HYBRIDENCRYPTOR_H
#define HYBRIDENCRYPTOR_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>

class HybridEncryptor
{
public:
    HybridEncryptor();
    ~HybridEncryptor();

    bool loadPublicKey(const std::string& pemFilePath);
    bool encryptFile(const std::string& inputFilePath,
                     const std::string& outputFilePath);

private:
    EVP_PKEY* rsaPublicKey = nullptr;

    bool encryptFileHybrid(const std::string& inputFilePath,
                           const std::string& outputFilePath,
                           EVP_PKEY* rsaPubKey);
};

#endif