#pragma once

#include <sys/types.h>
#include <arpa/inet.h>

#define ETHERNET_SIZE = 14
#define MAC_SIZE 6

typedef struct __ETHERNET__
{
    u_char *destMac;
    u_char *srcMac;
    u_short *type;
}Ethernet;

typedef struct __IP__
{

} IP;

typedef struct __TCP__
{

} TCP;

typedef struct __APPLICATION__
{

} Application;

typedef struct __PACKET__
{
    Ethernet ethernet;
    IP ip;
    TCP tcp;
    Application app;
} Packet;

Packet transPacket(const u_char *packetIn);
