cmake_minimum_required(VERSION 3.16)
project(HybridEncryptorServer)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(hybrid_server
    main.cpp
    HybridEncryptor.cpp
    HybridDecryptor.cpp
    applink.c
)

target_include_directories(hybrid_server PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    .
)

target_link_libraries(hybrid_server
    OpenSSL::Crypto
    OpenSSL::SSL
    ws2_32
    mswsock
)