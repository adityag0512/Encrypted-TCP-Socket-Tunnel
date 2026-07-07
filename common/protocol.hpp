#pragma once
#include <cstdint>   
#include <cstring>  


enum PacketType : uint8_t {
    PKT_DATA = 0x01,   
    PKT_PING = 0x02,   
    PKT_PONG = 0x03,   
    PKT_BYE  = 0x04, 
};


static const uint32_t PACKET_MAGIC = 0xCAFEBABE;


static const uint32_t MAX_PAYLOAD = 65535;


#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;    
    uint8_t  type;     
    uint32_t length;   
};
#pragma pack(pop)


inline void write_header(uint8_t* buf, PacketType type, uint32_t payload_len) {
    PacketHeader hdr;
    hdr.magic  = htonl(PACKET_MAGIC);
    hdr.type   = type;
    hdr.length = htonl(payload_len);
    std::memcpy(buf, &hdr, sizeof(PacketHeader));
}


inline bool read_header(const uint8_t* buf, PacketHeader& hdr) {
    std::memcpy(&hdr, buf, sizeof(PacketHeader));
    hdr.magic  = ntohl(hdr.magic);
    hdr.length = ntohl(hdr.length);

    
    if (hdr.magic != PACKET_MAGIC) return false;
    
    if (hdr.length > MAX_PAYLOAD)  return false;
    return true;
}


static const size_t HEADER_SIZE = sizeof(PacketHeader);