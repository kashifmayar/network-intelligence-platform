#include "nip/view/HttpServer.h"

#include "nip/view/Inspect.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(int fd) { return close(fd); }
#endif

namespace nip {
namespace {

constexpr std::size_t kMaxBody = 64 * 1024;

std::string readFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

bool sendAll(SOCKET client, const std::string& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const int wrote = send(client, bytes.data() + sent, static_cast<int>(bytes.size() - sent), 0);
        if (wrote <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(wrote);
    }
    return true;
}

std::string receiveRequest(SOCKET client) {
    std::string data;
    char buffer[4096];
    while (data.find("\r\n\r\n") == std::string::npos) {
        const int count = recv(client, buffer, sizeof(buffer), 0);
        if (count <= 0) {
            return {};
        }
        data.append(buffer, static_cast<std::size_t>(count));
        if (data.size() > kMaxBody + 8192) {
            return {};
        }
    }
    const auto headerEnd = data.find("\r\n\r\n");
    const auto header = data.substr(0, headerEnd);
    std::size_t contentLength = 0;
    const auto marker = header.find("Content-Length:");
    const auto markerLower = header.find("content-length:");
    const auto lengthAt = marker != std::string::npos ? marker : markerLower;
    if (lengthAt != std::string::npos) {
        contentLength = static_cast<std::size_t>(std::strtoul(header.c_str() + lengthAt + 15, nullptr, 10));
    }
    if (contentLength > kMaxBody) {
        return {};
    }
    const std::size_t bodyStart = headerEnd + 4;
    while (data.size() < bodyStart + contentLength) {
        const int count = recv(client, buffer, sizeof(buffer), 0);
        if (count <= 0) {
            return {};
        }
        data.append(buffer, static_cast<std::size_t>(count));
    }
    return data;
}

std::string response(int status, const char* reason, const char* contentType, const std::string& body) {
    std::ostringstream out;
    out << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
        << "Content-Type: " << contentType << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "Cache-Control: no-store\r\n\r\n"
        << body;
    return out.str();
}

std::string pathOf(const std::string& request) {
    const auto lineEnd = request.find("\r\n");
    const auto line = request.substr(0, lineEnd == std::string::npos ? request.size() : lineEnd);
    const auto firstSpace = line.find(' ');
    if (firstSpace == std::string::npos) {
        return {};
    }
    const auto secondSpace = line.find(' ', firstSpace + 1);
    if (secondSpace == std::string::npos) {
        return {};
    }
    return line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
}

std::string methodOf(const std::string& request) {
    const auto space = request.find(' ');
    if (space == std::string::npos) {
        return {};
    }
    return request.substr(0, space);
}

std::string bodyOf(const std::string& request) {
    const auto headerEnd = request.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return {};
    }
    return request.substr(headerEnd + 4);
}

void handleClient(SOCKET client, const std::string& uiDirectory) {
    const std::string request = receiveRequest(client);
    if (request.empty()) {
        closesocket(client);
        return;
    }
    const std::string method = methodOf(request);
    const std::string path = pathOf(request);
    std::string message;
    if (method == "GET" && (path == "/" || path == "/index.html")) {
        const std::string page = readFile(uiDirectory + "/index.html");
        if (page.empty()) {
            message = response(500, "Internal Server Error", "text/plain; charset=utf-8", "ui/index.html was not found\n");
        } else {
            message = response(200, "OK", "text/html; charset=utf-8", page);
        }
    } else if (method == "GET" && path == "/api/samples") {
        message = response(200, "OK", "application/json; charset=utf-8", sampleCatalogJson());
    } else if (method == "POST" && path == "/api/parse") {
        const auto bytes = decodeHex(bodyOf(request));
        if (!bytes.has_value()) {
            message = response(400, "Bad Request", "application/json; charset=utf-8",
                               "{\"error\":\"hex is empty, odd, or contains a non-hex character\"}");
        } else {
            message = response(200, "OK", "application/json; charset=utf-8",
                               inspectFrameJson(ByteView{bytes->data(), bytes->size()}));
        }
    } else {
        message = response(404, "Not Found", "text/plain; charset=utf-8", "not found\n");
    }
    sendAll(client, message);
    closesocket(client);
}

}  // namespace

int runInspector(const std::string& uiDirectory, unsigned short port) {
#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        std::cerr << "Winsock startup failed\n";
        return 1;
    }
#endif
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        std::cerr << "Could not open a socket\n";
        return 1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    const int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Could not bind 127.0.0.1:" << port << '\n';
        closesocket(listener);
        return 1;
    }
    if (listen(listener, 8) == SOCKET_ERROR) {
        std::cerr << "Could not listen\n";
        closesocket(listener);
        return 1;
    }
    std::cout << "Packet inspector: http://127.0.0.1:" << port << std::endl;
    for (;;) {
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }
        handleClient(client, uiDirectory);
    }
}

}  // namespace nip
