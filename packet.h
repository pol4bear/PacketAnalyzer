#pragma once

#include <sys/types.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14

#define TYPE_IP 0x0800

#define PROTOCOL_TCP 0x6

// TCP Flags
#define TCP_NONCE 0x100
#define TCP_CONGESTION 0x80
#define TCP_ECN 0x40
#define TCP_URGENT 0x20
#define TCP_ACK 0x10
#define TCP_PUSH 0x8
#define TCP_RESET 0x4
#define TCP_SYN 0x2
#define TCP_FIN 0x1

// TCP option locations
#define TCP_HEADERLEN 0xF000
#define TCP_FLAGS 0xFFF

typedef struct __ETHERNET__
{
    u_char destMac[6];
    u_char srcMac[6];
    u_short type;
}Ethernet;

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

typedef struct __TCP__
{
    u_short sourcePort;
    u_short destPort;
    u_int sequenceNumber;
    u_int acknowledgeNumber;
    u_short headerLengthAndFlags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
} TCP;

typedef struct __PACKET__
{
    Ethernet *ethernet;
    IP *ip;
    TCP *tcp;
    u_char tcpHeaderLength;
    u_short tcpFlags;
    u_short payloadLength;
    const u_char *payload;
} Packet;

void printPacketInfo(Packet packet);
Packet transPacket(const u_char *packetIn);
