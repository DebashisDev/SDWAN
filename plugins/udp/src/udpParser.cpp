/*
 * PUDP.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */


#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <algorithm>

#include "udpParser.h"

using namespace std;

udpParser::udpParser()
{
	this->udpHLen 	= 0;
	this->qdcount = 0;
	this->ancount = 0;
	this->dnsTLen = 0;
	this->pUt 		= new ProbeUtility();
}

udpParser::~udpParser()
{ delete(this->pUt); }

void udpParser::lockDnsMap()
{
	    pthread_mutex_lock(&mapDnsLock::lockCount);
	    while (mapDnsLock::count == 0)
	        pthread_cond_wait(&mapDnsLock::nonzero, &mapDnsLock::lockCount);
	    mapDnsLock::count = mapDnsLock::count - 1;
	    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void udpParser::unLockDnsMap()
{
    pthread_mutex_lock(&mapDnsLock::lockCount);
    if (mapDnsLock::count == 0)
        pthread_cond_signal(&mapDnsLock::nonzero);
    mapDnsLock::count = mapDnsLock::count + 1;
    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void udpParser::parseUDPPacket(const BYTE packet, MPacket *msgObj)
{ 
	udpHLen = 0;
	struct udphdr *udpHeader = (struct udphdr *)(packet);

 	udpHLen = ntohs((unsigned short int)udpHeader->len);
	msgObj->sPort = ntohs((unsigned short int)udpHeader->source);
	msgObj->dPort = ntohs((unsigned short int)udpHeader->dest);

	switch(msgObj->ipVer)
	{
		case IPVersion4:
			msgObj->ipv4FlowId = pUt->getIpv4SessionKey(msgObj->pType, msgObj->direction, msgObj->sIp, msgObj->dIp, msgObj->sPort, msgObj->dPort);
			break;

		case IPVersion6:
			/* IPv6 FlowId is generated in Session Manager */
			break;
	}

	msgObj->pLoad = msgObj->ipTLen - (msgObj->ipHLen + UDP_HDR_LEN);

	if(msgObj->pLoad > 0 && msgObj->pLoad >= Global::MAX_TCP_SIZE)
	{ msgObj->pLoad = Global::MAX_TCP_SIZE; }

    if((msgObj->sPort == DNS_PORT) || (msgObj->dPort == DNS_PORT))
    {
    	if(Global::DNS_ANSWER == 0) return;
    	lockDnsMap();
   		parsePacketDNS(packet + UDP_HDR_LEN, msgObj); // Total Length of UDP message (8)
    	unLockDnsMap();
    }
    return;
}


void udpParser::parsePacketDNS(const BYTE packet, MPacket *msgObj)
{
    uint32_t pos = 0, id_pos = 0, retPos = 0;

	if (msgObj->frSize - udpHLen < 12)
	{ return; }

	dnsTLen 				= udpHLen - UDP_HDR_LEN;
    msgObj->transactionId 	= (packet[pos] << 8) + packet[pos+1];		// Transaction ID
    msgObj->qrFlag 			= packet[pos+2] >> 7;					    // Query Response -> Question=0 and Answer=1

    switch(msgObj->qrFlag)
    {
		case QUERY:
				msgObj->pType = PACKET_IPPROTO_DNS;
				qdcount = (packet[pos+4] << 8) + packet[pos+5];			// Query Count

				if(qdcount == 1)
					if(!parsePacketDNSQueries(pos + DNS_HDR_LEN, id_pos, msgObj, packet, &retPos))
						return;
				break;

		case RESPONSE:
				msgObj->pType = PACKET_IPPROTO_DNS;
				qdcount = (packet[pos+4] << 8) + packet[pos+5];			// Query Count
				ancount = (packet[pos+6] << 8) + packet[pos+7];			// Answer Count

				msgObj->responseCode = packet[pos + 3] & 0x0f;		// rcode will be there in case of Response (Answer = 1)

				if (msgObj->responseCode != 0) // Earlier 26
					return;

				if(ancount >= Global::DNS_ANSWER)
					ancount = Global::DNS_ANSWER;

				if(qdcount == 1 && (ancount > 0 && ancount <= Global::DNS_ANSWER))
				{
					if(parsePacketDNSQueries((pos + DNS_HDR_LEN), id_pos, msgObj, packet, &retPos))
						if(msgObj->responseCode == 0)
							parsePacketDNSAnswers(retPos, msgObj, packet);
					else
						return;
				}
				break;

		default:
				msgObj->qrFlag 			= 3;		// Query Response -> Question=0 and Answer=1
				qdcount = ancount 		= 0;
				msgObj->transactionId 	= 3;		// Transaction ID
				break;
    }
}

bool udpParser::parsePacketDNSQueries(uint32_t pos, uint32_t id_pos, MPacket *msgObj, const BYTE packet, uint32_t *retPos)
{
    uint16_t type = 0;
    std::string url;

    url = read_rr_name(packet, &pos, id_pos, dnsTLen);
    std::replace(url.begin(), url.end(), ',', '.');

    if (url.compare("NULL") == 0)
    { return false; }

    if(url.length() >= URL_LEN)
    {
    	url = url.substr(url.length() - (URL_LEN - 1));
    	strcpy(msgObj->url, url.c_str());
    }
    else
    { strcpy(msgObj->url, url.c_str()); }

    url.clear();

    type = VAL_USHORT(packet+pos);

    if(type == 255) return false;	// 255 is for Any Ip Address

    *retPos = pos + 4;
    return true;
}

void udpParser::parsePacketDNSAnswers(uint32_t pos, MPacket *msgObj, const BYTE packet)
{
	uint16_t type, dataLen, ttl;
//	char ipv6ResolvedIp[INET6_ADDRSTRLEN];

	std::string addressList = "";
	dataLen = ttl = 0;

	try
	{
		for(uint16_t ansCounter = 0; ansCounter < ancount; ansCounter++)
		{
			while(packet[pos] != 192) { // Reference Question Name Start with '0xc0' locate it
				pos += 1;
			}

			pos = pos + 2;												// Reference Question Name (2 Bytes)
			type = (packet[pos] << 8) + packet[pos + 1];

			pos = pos + 2;												// Type
			pos = pos + 2;												// Class
			pos = pos + 4;												// TTL

			dataLen = (packet[pos] << 8) + packet[pos + 1];
			pos = pos + 2;												// Data Length

			uint32_t longResolvedIp = 0;

			switch(type)
			{
				case A:	/* IP4 Address */
					msgObj->responseCode = 0;

					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 1]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 2]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 3]);

					if((longResolvedIp >= 16777216 && longResolvedIp <= 4294967295) && strlen(msgObj->url) > 0)
					{
						updateUrl(longResolvedIp, std::string(msgObj->url));
						addressList = "";
						addressList.assign(std::to_string(longResolvedIp));
					}

					/* 2 Bytes already increased in case of Name */
					pos = pos + dataLen;

					break;

//				case AAAA: /* IP6 Address */
//					msgObj->responseCode = 0;
//					if(Global::IPV6_PROCESSING)
//					{
//						pUt->ExtractIP6Address(packet, ipv6ResolvedIp, pos);
//
//						updateV6Url(std::string(ipv6ResolvedIp), std::string(msgObj->url));
//						addressList.assign(std::string(ipv6ResolvedIp));
//						addressList = "";
//					}
//					pos = pos + dataLen;
//					ipv6ResolvedIp[0] = 0;
//					break;

				default:
					addressList = "";
					addressList.assign("No HostAddress");
					pos = pos + dataLen;
					break;
			}
		}

//		ipv6ResolvedIp[0] = 0;
		msgObj->resolvedIp[0] = 0;

		if(msgObj->responseCode == 0 && addressList.empty())
			strcpy(msgObj->resolvedIp, "NULL");
		else
			strcpy(msgObj->resolvedIp, addressList.c_str());
	}
	catch(const std::exception& e)
	{ std::cout << " a standard exception was caught, with message '" << e.what() << "'\n"; }
}

string udpParser::read_rr_name(const BYTE packet, uint32_t* packet_p, uint32_t id_pos, uint16_t len)
{
    uint32_t i, next, pos=*packet_p;
    uint32_t end_pos = 0;
    uint32_t name_len=0;
    uint32_t steps = 0;

    next = pos;

    while (pos < len && !(next == pos && packet[pos] == 0) && steps < len*2)
    {
        uint8_t c = packet[pos];
        steps++;
        if (next == pos) {
            if ((c & 0xc0) == 0xc0) {
                if (pos + 1 >= len){
                	return "NULL";
                }
                if (end_pos == 0) end_pos = pos + 1;
                pos = id_pos + ((c & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                name_len++;
                pos++;
                next = next + c + 1;
            }
        } else {
            if (c >= '!' && c <= 'z' && c != '\\') name_len++;
            else name_len += 4;
            pos++;
        }
    }
    if (end_pos == 0) end_pos = pos;

    if (steps >= 2*len || pos >= len)
    	return "NULL";

    name_len++;

    if(name_len > len *2)
    	return "NULL";

    string name;
    pos = *packet_p;

    next = pos;
    i = 0;
    while (next != pos || packet[pos] != 0) {
        if (pos == next) {
            if ((packet[pos] & 0xc0) == 0xc0) {
                pos = id_pos + ((packet[pos] & 0x3f) << 8) + packet[pos+1];
                next = pos;
            } else {
                // Add a period except for the first time.
                if (i != 0) name.append(1,'.');i++;
                next = pos + packet[pos] + 1;
                pos++;
            }
        } else {
            uint8_t c = packet[pos];
            if (c >= '!' && c <= '~' && c != '\\') {
                name.append(1, (char) c);
                i++; pos++;
            } else {
            	return "NULL";
            }
        }
    }
    *packet_p = end_pos + 1;
    return name;
}
