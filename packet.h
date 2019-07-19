#pragma once

#include <sys/types.h>
#include <arpa/inet.h>

// Static header lengths
#define SIZE_ETHERNET 14

// Ethernet header ethertypes
#define TYPE_IP 0x0800

// IP header protocol types
#define PROTOCOL_TCP 0x6

// TCP flags
#define TCP_RESERVED_NONCE 0x1
#define TCP_FLAGS_CONGESTION 0x80
#define TCP_FLAGS_ECN 0x40
#define TCP_FLAGS_URGENT 0x20
#define TCP_FLAGS_ACK 0x10
#define TCP_FLAGS_PUSH 0x8
#define TCP_FLAGS_RESET 0x4
#define TCP_FLAGS_SYN 0x2
#define TCP_FLAGS_FIN 0x1

// TCP option locations
#define TCP_HEADERLEN 0xF000
#define TCP_FLAGS 0xFFF

// Ethernet header
typedef struct __ETHERNET__
{
    u_char destMac[6];
    u_char srcMac[6];
    u_short type;
}Ethernet;

// IP header
typedef struct __IP__
{
    u_char headerLength : 4;
    u_char version : 4;
    u_char serviceType;
    u_short totalLength;
    u_short identification;
    u_short flags;
    u_char timeToLive;
    u_char protocol;
    u_short headerChecksum;
    u_char sourceIP[4];
    u_char destIP[4];
} IP;

// TCP header
typedef struct __TCP__
{
    u_short sourcePort;
    u_short destPort;
    u_int sequenceNumber;
    u_int acknowledgeNumber;
    u_char reserved : 4;
    u_char headerLength : 4;
    u_char flags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
} TCP;

// TCP packet
typedef struct __PACKET__
{
    Ethernet *ethernet;
    IP *ip;
    TCP *tcp;
    int payloadLength;
    const u_char *payload;
} Packet;

// Prints certain packet info from TCP packet
void printPacketInfo(Packet packet);

// Set TCP packet parameters from raw packet
Packet transPacket(const u_char *packetIn);
