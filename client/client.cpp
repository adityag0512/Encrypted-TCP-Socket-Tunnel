#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>        

#include "../common/logger.hpp"
#include "../common/protocol.hpp"
#include "../common/crypto.hpp"
#include "../common/socket_utils.hpp"

struct TunnelStats {
    uint64_t packets_sent  = 0;
    uint64_t packets_recv  = 0;
    uint64_t bytes_sent    = 0;
    uint64_t bytes_recv    = 0;
    uint64_t encrypt_time_us = 0;  
    uint64_t decrypt_time_us = 0; 
};

void receive_thread(int sock_fd, Crypto& crypto, TunnelStats& stats,
                    std::atomic<bool>& connected) {
    while (connected) {
        PacketType type;
        std::vector<uint8_t> payload;

        if (!recv_packet(sock_fd, type, payload)) {
            if (connected) {
                log_warn("Connection to server lost.");
                connected = false;
            }
            break;
        }

        stats.packets_recv++;
        stats.bytes_recv += HEADER_SIZE + payload.size();

        if (type == PKT_PONG) {
            log_debug("PONG received (server is alive)");
        }
        else if (type == PKT_BYE) {
            log_info("Server sent BYE — disconnecting.");
            connected = false;
            break;
        }
        else if (type == PKT_DATA) {
            try {
                
                auto t0 = std::chrono::high_resolution_clock::now();
                std::vector<uint8_t> plaintext = crypto.decrypt(payload);
                auto t1 = std::chrono::high_resolution_clock::now();
                stats.decrypt_time_us += std::chrono::duration_cast<
                    std::chrono::microseconds>(t1 - t0).count();

                std::string msg(plaintext.begin(), plaintext.end());
                
                std::cout << "\n[TUNNEL] Received: " << msg << "\n";
                std::cout << "client> ";
                std::cout.flush();
            }
            catch (const std::exception& e) {
                log_error(std::string("Decryption error: ") + e.what());
            }
        }
    }
}


std::string format_bytes(uint64_t bytes) {
    std::ostringstream oss;
    if (bytes < 1024)
        oss << bytes << " B";
    else if (bytes < 1024*1024)
        oss << std::fixed << std::setprecision(2) << bytes/1024.0 << " KB";
    else
        oss << std::fixed << std::setprecision(2) << bytes/(1024.0*1024) << " MB";
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server-ip> <port> <encryption-key>\n";
        std::cerr << "Example: ./client 127.0.0.1 9000 mysecretkey\n";
        return 1;
    }

    std::string server_ip  = argv[1];
    int         port       = std::stoi(argv[2]);
    std::string key        = argv[3];

    log_info("VPN Tunnel Client starting...");
    log_info("Target: " + server_ip + ":" + std::to_string(port));
    log_info("Encryption: AES-256-GCM");

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        log_error("Failed to create socket");
        return 1;
    }

   
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);

    
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        log_error("Invalid server IP address: " + server_ip);
        close(sock_fd);
        return 1;
    }

    
    log_info("Connecting to server...");
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed. Is the server running?");
        close(sock_fd);
        return 1;
    }

    log_info("✓ Connected! Tunnel established.\n");

    
    Crypto crypto(key);

    
    TunnelStats stats;
    std::atomic<bool> connected{true};
    std::thread recv_t(receive_thread, sock_fd, std::ref(crypto),
                       std::ref(stats), std::ref(connected));

    
    std::cout << "=== VPN Tunnel Client CLI ===\n";
    std::cout << "Commands:\n";
    std::cout << "  <any text>  — send text through the encrypted tunnel\n";
    std::cout << "  ping        — send a ping to the server\n";
    std::cout << "  stats       — show tunnel statistics\n";
    std::cout << "  quit        — disconnect and exit\n\n";

    std::string input;
    while (connected) {
        std::cout << "client> ";
        std::cout.flush();

        if (!std::getline(std::cin, input)) break; 
        if (input.empty()) continue;

        

        if (input == "quit" || input == "exit") {
            log_info("Sending BYE to server...");
            std::vector<uint8_t> empty;
            send_packet(sock_fd, PKT_BYE, empty);
            connected = false;
            break;
        }

        if (input == "ping") {
            log_info("Sending PING...");
            std::vector<uint8_t> empty;
            send_packet(sock_fd, PKT_PING, empty);
            stats.packets_sent++;
            continue;
        }

        if (input == "stats") {
            std::cout << "\n--- Tunnel Statistics ---\n";
            std::cout << "Packets sent:      " << stats.packets_sent  << "\n";
            std::cout << "Packets received:  " << stats.packets_recv  << "\n";
            std::cout << "Data sent:         " << format_bytes(stats.bytes_sent) << "\n";
            std::cout << "Data received:     " << format_bytes(stats.bytes_recv) << "\n";
            if (stats.packets_sent > 0) {
                std::cout << "Avg encrypt time:  "
                          << (stats.encrypt_time_us / stats.packets_sent)
                          << " µs/packet\n";
            }
            if (stats.packets_recv > 0) {
                std::cout << "Avg decrypt time:  "
                          << (stats.decrypt_time_us / stats.packets_recv)
                          << " µs/packet\n";
            }
            std::cout << "\n";
            continue;
        }

        

        
        std::vector<uint8_t> plaintext(input.begin(), input.end());

        
        std::vector<uint8_t> encrypted;
        try {
            auto t0 = std::chrono::high_resolution_clock::now();
            encrypted = crypto.encrypt(plaintext);
            auto t1 = std::chrono::high_resolution_clock::now();
            stats.encrypt_time_us += std::chrono::duration_cast<
                std::chrono::microseconds>(t1 - t0).count();
        }
        catch (const std::exception& e) {
            log_error(std::string("Encryption failed: ") + e.what());
            continue;
        }

        
        if (!send_packet(sock_fd, PKT_DATA, encrypted)) {
            log_error("Failed to send — connection may be closed.");
            connected = false;
            break;
        }

        stats.packets_sent++;
        stats.bytes_sent += HEADER_SIZE + encrypted.size();

        log_debug("Sent " + std::to_string(plaintext.size()) +
                  " bytes (encrypted to " + std::to_string(encrypted.size()) + " bytes)");
    }

    close(sock_fd);
    if (recv_t.joinable()) recv_t.join();

    std::cout << "\n--- Final Session Stats ---\n";
    std::cout << "Total sent:     " << format_bytes(stats.bytes_sent) << "\n";
    std::cout << "Total received: " << format_bytes(stats.bytes_recv) << "\n";
    log_info("Client disconnected. Goodbye.");
    return 0;
}