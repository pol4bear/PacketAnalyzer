#include "packet.h"
#include <stdio.h>
#include <memory>

char* formatMac(u_char *mac)
{
    char *ret = reinterpret_cast<char*>(malloc(17));

    sprintf(ret, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return ret;
}

char* formatIP(u_char *ip)
{
    char *res = reinterpret_cast<char*>(malloc(15));

    sprintf(res, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return res;
}

void printPacketInfo(Packet packet)
{
    if(packet.ethernet != nullptr)
    {
        printf("===============================\n");
        printf("Src MAC: %s\n", formatMac(packet.ethernet->destMac));
        printf("Dest MAC: %s\n", formatMac(packet.ethernet->srcMac));

        if(packet.ip != nullptr)
        {
            printf("Src IP: %s\n", formatIP(packet.ip->sourceIP));
            printf("Dest IP: %s\n", formatIP(packet.ip->destIP));

            if(packet.tcp != nullptr)
            {
                printf("Src Port: %d\n", ntohs(packet.tcp->sourcePort));
                printf("Dest Port: %d\n", ntohs(packet.tcp->destPort));
            }

            if(packet.payloadLength > 0)
            {
                printf("Payload length: %d\n", packet.payloadLength);
                printf("Last 10 byte of payload: ");
                for(int i = 0; i<10; i++)
                {
                    if(i == packet.payloadLength)
                        break;

                    printf("%02X ", packet.payload[i]);
                }

                printf("\n");
            }
        }
    }
}

Packet transPacket(const u_char *packetIn)
{
    Packet res { nullptr, nullptr, nullptr, 0, nullptr };
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

            translatedBytes += res.tcp->headerLength * 4;

            res.payloadLength = htons(res.ip->totalLength) - res.ip->headerLength * 4 - res.tcp->headerLength * 4;
            res.payload = &packetIn[translatedBytes];
        }
    }

    return res;
}
