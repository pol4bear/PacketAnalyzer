#include "packet.h"

Packet transPacket(const u_char *packetIn)
{
    Packet ret;
    int translatedBytes = 0;

    u_short preamble = *packetIn;

    if(preamble == PREAMBLE)
    {
        translatedBytes += SIZE_PREAMBLE;
        ret.ethernet = (Ethernet*)&packetIn[translatedBytes];
        translatedBytes += SIZE_ETHERNET;


        if(ret.ethernet->type == TYPE_IP)
        {
            ret.ip = (IP*)&packetIn[translatedBytes];
            translatedBytes += ret.ip->headerLength;

            if(ret.ip->protocol == PROTOCOL_TCP)
            {
                ret.tcp = (TCP*)&packetIn[translatedBytes];
                translatedBytes += ret.tcp->headerLength;

                ret.payload_len = ret.ip->totalLength - ret.ip->headerLength - ret.tcp->headerLength;
                ret.payload = &packetIn[translatedBytes];
            }
        }
    }

    return ret;
}
