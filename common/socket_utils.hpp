#pragma once
#include <sys/socket.h>   
#include <unistd.h>      
#include <cstdint>
#include <vector>
#include <stdexcept>

inline bool send_all(int fd, const uint8_t* buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        
        ssize_t sent = send(fd, buf + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (sent <= 0) return false; 
        total_sent += sent;
    }
    return true;
}


inline bool recv_all(int fd, uint8_t* buf, size_t len) {
    size_t total_recv = 0;
    while (total_recv < len) {
        ssize_t received = recv(fd, buf + total_recv, len - total_recv, 0);
        if (received <= 0) return false;  
        total_recv += received;
    }
    return true;
}


inline bool send_packet(int fd, PacketType type, const std::vector<uint8_t>& payload) {
    
    size_t total = HEADER_SIZE + payload.size();
    std::vector<uint8_t> buf(total);

    
    write_header(buf.data(), type, (uint32_t)payload.size());

    
    if (!payload.empty() && payload.size() <= MAX_PAYLOAD) {
        std::memcpy(buf.data() + HEADER_SIZE, payload.data(), payload.size());
    }
    
    return send_all(fd, buf.data(), total);
}

inline bool recv_packet(int fd, PacketType& type, std::vector<uint8_t>& payload) {
    
    uint8_t hdr_buf[HEADER_SIZE];
    if (!recv_all(fd, hdr_buf, HEADER_SIZE)) return false;

    PacketHeader hdr;
    if (!read_header(hdr_buf, hdr)) return false; 

    type = (PacketType)hdr.type;

    
    payload.resize(hdr.length);
    if (hdr.length > 0) {
        if (!recv_all(fd, payload.data(), hdr.length)) return false;
    }

    return true;
}