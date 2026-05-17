#define NOMINMAX
#define _WIN32_WINNT 0x0601
#include "crow_all.h"
#include "hybridencryptor.h"
#include "HybridDecryptor.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <cstdio>

// ── Base64 ────────────────────────────────────────────────────────
static const std::string B64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const unsigned char* buf, size_t len)
{
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + buf[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(B64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<unsigned char> base64Decode(const std::string& in)
{
    std::vector<unsigned char> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)B64[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue; // ignore padding/whitespace
        }
        if (T[c] == -1) {
            continue; // ignore unexpected chars
        }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

std::string tmpPath(const std::string& suffix)
{
    return "tmp_" + std::to_string(std::time(nullptr))
        + "_" + std::to_string(rand()) + suffix;
}

void addCors(crow::response& res)
{
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");
}

int main()
{
    crow::SimpleApp app;

    // ── Serve frontend ────────────────────────────────────────────
    CROW_ROUTE(app, "/")
        ([](const crow::request&) {
        std::ifstream f("index.html");
        std::string body((std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
        crow::response res;
        addCors(res);
        res.code = 200;
        res.write(body);
        res.add_header("Content-Type", "text/html");
        return res;
            });

    // ── Health check ──────────────────────────────────────────────
    CROW_ROUTE(app, "/api/health").methods("GET"_method, "OPTIONS"_method)
        ([](const crow::request& req) {
        crow::response res;
        addCors(res);
        if (req.method == crow::HTTPMethod::Options) {
            res.code = 204;
            return res;
        }
        crow::json::wvalue body;
        body["status"] = "running";
        body["algorithm"] = "AES-256-CBC + RSA-2048";
        res.code = 200;
        res.write(body.dump());
        res.add_header("Content-Type", "application/json");
        return res;
            });

    // ── Encrypt ───────────────────────────────────────────────────
    CROW_ROUTE(app, "/api/encrypt").methods("POST"_method, "OPTIONS"_method)
        ([](const crow::request& req) {
        crow::response res;
        addCors(res);
        if (req.method == crow::HTTPMethod::Options) {
            res.code = 204;
            return res;
        }

        auto json = crow::json::load(req.body);
        if (!json) {
            res.code = 400;
            res.write("{\"error\":\"Invalid JSON\"}");
            return res;
        }

        std::string b64data = json["data"].s();
        std::vector<unsigned char> rawBytes = base64Decode(b64data);

        std::string inPath = tmpPath(".bin");
        std::string outPath = tmpPath(".enc");

        {
            std::ofstream f(inPath, std::ios::binary);
            f.write(reinterpret_cast<char*>(rawBytes.data()), rawBytes.size());
        }

        HybridEncryptor enc;
        if (!enc.loadPublicKey("public_key.pem")) {
            std::remove(inPath.c_str());
            res.code = 500;
            res.write("{\"error\":\"Failed to load public key\"}");
            return res;
        }

        if (!enc.encryptFile(inPath, outPath)) {
            std::remove(inPath.c_str());
            res.code = 500;
            res.write("{\"error\":\"Encryption failed\"}");
            return res;
        }

        std::ifstream f(outPath, std::ios::binary | std::ios::ate);
        std::streamsize sz = f.tellg();
        f.seekg(0);
        std::vector<unsigned char> buf(sz);
        f.read(reinterpret_cast<char*>(buf.data()), sz);
        f.close();

        std::remove(inPath.c_str());
        std::remove(outPath.c_str());

        crow::json::wvalue body;
        body["success"] = true;
        body["encryptedData"] = base64Encode(buf.data(), buf.size());
        body["fileSize"] = (int)sz;
        res.code = 200;
        res.write(body.dump());
        res.add_header("Content-Type", "application/json");
        return res;
            });

    // ── Decrypt ───────────────────────────────────────────────────
    CROW_ROUTE(app, "/api/decrypt").methods("POST"_method, "OPTIONS"_method)
        ([](const crow::request& req) {
        crow::response res;
        addCors(res);
        if (req.method == crow::HTTPMethod::Options) {
            res.code = 204;
            return res;
        }

        auto json = crow::json::load(req.body);
        if (!json) {
            res.code = 400;
            res.write("{\"error\":\"Invalid JSON\"}");
            return res;
        }

        std::string b64data = json["data"].s();
        std::vector<unsigned char> rawBytes = base64Decode(b64data);

        std::string inPath = tmpPath(".enc");
        std::string outPath = tmpPath(".bin");

        {
            std::ofstream f(inPath, std::ios::binary);
            f.write(reinterpret_cast<char*>(rawBytes.data()), rawBytes.size());
        }

        HybridDecryptor dec;
        if (!dec.loadPrivateKey("private_key.pem")) {
            std::remove(inPath.c_str());
            res.code = 500;
            res.write("{\"error\":\"Failed to load private key\"}");
            return res;
        }

        if (!dec.decryptFile(inPath, outPath)) {
            std::remove(inPath.c_str());
            res.code = 500;
            res.write("{\"error\":\"Decryption failed\"}");
            return res;
        }

        std::ifstream f(outPath, std::ios::binary | std::ios::ate);
        std::streamsize sz = f.tellg();
        f.seekg(0);
        std::vector<unsigned char> buf(sz);
        f.read(reinterpret_cast<char*>(buf.data()), sz);
        f.close();

        std::remove(inPath.c_str());
        std::remove(outPath.c_str());

        crow::json::wvalue body;
        body["success"] = true;
        body["decryptedData"] = base64Encode(buf.data(), buf.size());
        body["fileSize"] = (int)sz;
        res.code = 200;
        res.write(body.dump());
        res.add_header("Content-Type", "application/json");
        return res;
            });

    std::cout << "Server running on http://0.0.0.0:8080" << std::endl;
    std::cout << "Open browser and go to http://localhost:8080" << std::endl;
    app.port(8080).multithreaded().run();
    return 0;
}