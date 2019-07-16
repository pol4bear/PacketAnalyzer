#pragma once

#include <sys/types.h>
#include <arpa/inet.h>

#define SIZE_PREAMBLE 8
#define SIZE_ETHERNET 22

#define PREAMBLE 0xAAAB

#define TYPE_IP 0x0800

#define PROTOCOL_TCP 0x6

#define TCP_NONCE 0x100
#define TCP_CONGESTION 0x80
#define TCP_ECN 0x40
#define TCP_URGENT 0x20
#define TCP_ACK 0x10
#define TCP_PUSH 0x8
#define TCP_RESET 0x4
#define TCP_SYN 0x2
#define TCP_FIN 0x1

typedef struct __ETHERNET__
{
    u_short destMac : 6;
    u_short srcMac : 6;
    u_short type;
}Ethernet;

typedef struct __IP__
{
    u_char version : 4;
    u_char headerLength : 4;
    u_char serviceType;
    u_short totalLength;
    u_short identification;
    u_char flags : 3;
    u_short fragmentOffset : 13;
    u_char timeToLive;
    u_char protocol;
    u_short headerChecksum;
    u_int sourceIP;
    u_int destIP;
} IP;
typedef struct __TCP__
{
    u_short sourcePort;
    u_short destPort;
    u_int sequenceNumber;
    u_int acknowledgeNumber;
    u_char headerLength : 4;
    u_char reserved : 3;
    u_int flags : 9;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
} TCP;

typedef struct __PACKET__
{
    Ethernet *ethernet;
    IP *ip;
    TCP *tcp;
    u_short payload_len;
    const u_char *payload;
} Packet;

Packet transPacket(const u_char *packetIn);
