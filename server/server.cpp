#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <sstream>
#include <sys/socket.h>  
#include <netinet/in.h>   
#include <arpa/inet.h>   
#include <unistd.h>      


#include "../common/logger.hpp"
#include "../common/protocol.hpp"
#include "../common/crypto.hpp"
#include "../common/socket_utils.hpp"


struct Session {
    int         fd;          
    std::string client_ip;    
    int         client_port;  
    uint64_t    bytes_recv;   
    uint64_t    bytes_sent;   
    std::string connected_at;
};


std::map<int, Session> sessions;
std::mutex sessions_mutex;
std::atomic<int> next_session_id{1};


void handle_client(int client_fd, std::string client_ip, int client_port,
                   int session_id, Crypto& crypto) {
    log_info("Session " + std::to_string(session_id) +
             " started with " + client_ip + ":" + std::to_string(client_port));

    uint64_t bytes_recv = 0;
    uint64_t bytes_sent = 0;

    
    while (true) {
        PacketType type;
        std::vector<uint8_t> payload;

        
        if (!recv_packet(client_fd, type, payload)) {
            log_info("Session " + std::to_string(session_id) +
                     " — client disconnected.");
            break;
        }

        bytes_recv += HEADER_SIZE + payload.size();

        
        if (type == PKT_BYE) {
            
            log_info("Session " + std::to_string(session_id) +
                     " — received BYE, closing.");
            break;
        }
        else if (type == PKT_PING) {
            
            log_debug("Session " + std::to_string(session_id) + " — PING received, sending PONG");
            std::vector<uint8_t> empty;
            send_packet(client_fd, PKT_PONG, empty);
        }
        else if (type == PKT_DATA) {
            
            try {
                std::vector<uint8_t> plaintext = crypto.decrypt(payload);

                
                std::string msg(plaintext.begin(), plaintext.end());
                log_info("Session " + std::to_string(session_id) +
                         " — received " + std::to_string(plaintext.size()) +
                         " bytes: \"" + msg + "\"");

                
                std::string reply_str = "SERVER_ECHO: " + msg;
                std::vector<uint8_t> reply_plain(reply_str.begin(), reply_str.end());
                std::vector<uint8_t> reply_enc = crypto.encrypt(reply_plain);

                if (!send_packet(client_fd, PKT_DATA, reply_enc)) {
                    log_error("Session " + std::to_string(session_id) + " — failed to send reply");
                    break;
                }
                bytes_sent += HEADER_SIZE + reply_enc.size();

                log_debug("Session " + std::to_string(session_id) +
                          " — sent reply (" + std::to_string(reply_enc.size()) + " encrypted bytes)");
            }
            catch (const std::exception& e) {
                
                log_error("Session " + std::to_string(session_id) +
                          " — decryption error: " + e.what());
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            if (sessions.count(session_id)) {
                sessions[session_id].bytes_recv = bytes_recv;
                sessions[session_id].bytes_sent = bytes_sent;
            }
        }
    }

    close(client_fd);
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        sessions.erase(session_id);
    }
    log_info("Session " + std::to_string(session_id) + " cleaned up. " +
             "Recv: " + std::to_string(bytes_recv) + "B, " +
             "Sent: " + std::to_string(bytes_sent) + "B");
}


void cli_thread(std::atomic<bool>& running, int listen_fd) {
    std::cout << "\n=== VPN Tunnel Server CLI ===\n";
    std::cout << "Commands: status | quit\n\n";

    std::string cmd;
    while (running) {
        std::cout << "server> ";
        std::cout.flush();

        if (!std::getline(std::cin, cmd)) break;

        if (cmd == "status") {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            if (sessions.empty()) {
                std::cout << "No active sessions.\n";
            } else {
                std::cout << "\n--- Active Sessions ---\n";
                std::cout << std::left
                          << std::setw(6)  << "ID"
                          << std::setw(18) << "Client IP"
                          << std::setw(8)  << "Port"
                          << std::setw(12) << "Recv(B)"
                          << std::setw(12) << "Sent(B)"
                          << "\n";
                std::cout << std::string(56, '-') << "\n";
                for (auto& [id, sess] : sessions) {
                    std::cout << std::left
                              << std::setw(6)  << id
                              << std::setw(18) << sess.client_ip
                              << std::setw(8)  << sess.client_port
                              << std::setw(12) << sess.bytes_recv
                              << std::setw(12) << sess.bytes_sent
                              << "\n";
                }
                std::cout << "\n";
            }
        }
        else if (cmd == "quit" || cmd == "exit") {
            std::cout << "Shutting down server...\n";
            running = false;
            
            shutdown(listen_fd, SHUT_RDWR);
            break;
        }
        else if (!cmd.empty()) {
            std::cout << "Unknown command. Try: status | quit\n";
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <encryption-key>\n";
        std::cerr << "Example: ./server 9000 mysecretkey\n";
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string key = argv[2];

    log_info("Starting VPN Tunnel Server on port " + std::to_string(port));
    log_info("Encryption: AES-256-GCM");

    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_error("Failed to create socket");
        return 1;
    }

    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    
    struct sockaddr_in server_addr{};
    server_addr.sin_family      = AF_INET;          
    server_addr.sin_addr.s_addr = INADDR_ANY;       
    server_addr.sin_port        = htons(port);      

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to bind to port " + std::to_string(port));
        close(listen_fd);
        return 1;
    }

    
    if (listen(listen_fd, 5) < 0) {
        log_error("Failed to listen");
        close(listen_fd);
        return 1;
    }

    log_info("Server listening on 0.0.0.0:" + std::to_string(port));
    log_info("Waiting for clients...\n");

    
    Crypto crypto(key);

    
    std::atomic<bool> running{true};
    std::thread cli(cli_thread, std::ref(running), listen_fd);

    
    while (running) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);

        
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (running) log_error("accept() failed");
            break;
        }

        
        std::string client_ip   = inet_ntoa(client_addr.sin_addr);
        int         client_port = ntohs(client_addr.sin_port);

        int session_id = next_session_id++;

       
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            sessions[session_id] = Session{
                client_fd, client_ip, client_port, 0, 0, current_time()
            };
        }

        log_info("New connection from " + client_ip + ":" +
                 std::to_string(client_port) + " (Session " +
                 std::to_string(session_id) + ")");

        
        std::thread t(handle_client, client_fd, client_ip, client_port,
                      session_id, std::ref(crypto));
        t.detach();
    }


    close(listen_fd);
    if (cli.joinable()) cli.join();

    log_info("Server shut down.");
    return 0;
}