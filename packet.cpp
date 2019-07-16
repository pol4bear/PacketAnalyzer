#include "packet.h"

Packet transPacket(const u_char *packetIn)
{
    Packet ret;

    ret.ethernet.destMac = &packet[8];
    ret.ethernet.destMac[1] = packet[9];
    ret.ethernet.destMac[2] = packet[10];
    ret.ethernet.destMac[3] = packet[11];
    ret.ethernet.destMac[4] = packet[12];
    ret.ethernet.destMac[5] = packet[13];
    ret.ethernet.srcMac[0] = packet[14];
    ret.ethernet.srcMac[1] = packet[15];
    ret.ethernet.srcMac[2] = packet[16];
    ret.ethernet.srcMac[3] = packet[17];
    ret.ethernet.srcMac[4] = packet[18];
    ret.ethernet.srcMac[5] = packet[19];
    ret.ethernet.type =

    return ret;
}
