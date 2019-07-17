#include "packet.h"
#include <stdio.h>

char* formatMac(u_char *mac)
{
    char res[17] = { 0, };

    sprintf(res, "%2X:%2X:%2X:%2X:%2X:%2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return res;
}

char* formatIP(u_char *ip)
{
    char res[15] = { 0, };

    sprintf(res, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return res;
}

void printPacketInfo(Packet packet)
{
    if(packet.ethernet != nullptr)
    {
        printf("Src MAC: %s\n", formatMac(packet.ethernet->srcMac));
        printf("Dest MAC: %s\n", formatMac(packet.ethernet->destMac));

        if(packet.ip != nullptr)
        {
            printf("Src IP: %s\n", formatIP(packet.ip->sourceIP));
            printf("Dest IP: %s\n", formatIP(packet.ip->destIP));

            if(packet.tcp != nullptr)
            {
                printf("Src Port: %d\n", ntohs(packet.tcp->sourcePort));
                printf("Dest Port: %d\n", ntohs(packet.tcp->destPort));
            }
        }
    }
    //printf("payload length: %d  %d\n", packet.payloadLength, htons(packet.ip->totalLength));
    //printf("First 10 data: %X %X %X %X %X %X %X %X %X %X\n", packet.payload[0], packet.payload[1],packet.payload[2],packet.payload[3],packet.payload[4],packet.payload[5],packet.payload[6],packet.payload[7],packet.payload[8],packet.payload[9]);
}

Packet transPacket(const u_char *packetIn)
{
    Packet res { nullptr, nullptr, nullptr, 0, 0, 0, nullptr };
    int translatedBytes = 0;

    res.ethernet = reinterpret_cast<Ethernet*>(const_cast<u_char*>(&packetIn[translatedBytes]));
    translatedBytes += SIZE_ETHERNET;

    if(htons(res.ethernet->type) == TYPE_IP)
    {
        res.ip = reinterpret_cast<IP*>(const_cast<u_char*>(&packetIn[translatedBytes]));
        translatedBytes += res.ip->headerLength * 4;

        if(res.ip->protocol == PROTOCOL_TCP)
        {
            res.tcp = reinterpret_cast<TCP*>(const_cast<u_char*>(&packetIn[translatedBytes]));
            u_short tcpHeaderLengthAndFlags = ntohs(res.tcp->headerLengthAndFlags);
            res.tcpHeaderLength = (tcpHeaderLengthAndFlags & TCP_HEADERLEN) >> 12;
            res.tcpFlags = tcpHeaderLengthAndFlags & TCP_FLAGS;

            translatedBytes += res.tcpHeaderLength * 4;

            res.payloadLength = htons(res.ip->totalLength) - res.ip->headerLength * 4 - res.tcpHeaderLength * 4;
            res.payload = &packetIn[translatedBytes];
        }
    }

    return res;
}
