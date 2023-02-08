/*
 * EthernetProbe.cpp
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#include <sys/time.h>
#include <arpa/inet.h>

#include "EthernetParser.h"

EthernetParser::EthernetParser(uint16_t intfid, uint16_t rId)
{
	this->_name = "EthernetParser";
	this->setLogLevel(Log::theLog().level());

	this->interfaceId = intfid;
	this->routerId = rId;

	this->tcp 	= new tcpParser();
	this->udp 	= new udpParser();
	this->pUt 	= new ProbeUtility();

	ip4Header 	= NULL;
	ip6Header 	= NULL;
	udpHeader 	= NULL;

	ethOffset	= 12;
	packetSize	= 0;
	ptr_vlan_t 	= NULL;
	type 		= 0;
}

EthernetParser::~EthernetParser()
{
	delete (this->tcp);
	delete (this->udp);
	delete(this->pUt);
}

void EthernetParser::hexDump(const void* pv, uint16_t len)
{
  const unsigned char* p = (const unsigned char*) pv;
  uint16_t i;

  for( i = 0; i < len; ++i )
  {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
}

void EthernetParser::parsePacket(const BYTE packet, MPacket *msgObj)
{
	uint16_t type = packet[ethOffset] * 256 + packet[ethOffset + 1];		/* Ethernet Containing Protocol */

    switch(type)
     {
     	case ETH_IP:
     			fn_decodeIPv4(packet + sizeof(struct ether_header), msgObj);
     			break;
     	case ETH_8021Q:
     			fn_decode8021Q(packet + sizeof(struct ether_header), msgObj);
     			break;
     	case ETH_MPLS_UC:
     			fn_decodeMPLS(packet + sizeof(struct ether_header), msgObj);
     			break;
     	default:
     		break;
     }
}

void EthernetParser::fn_decodeMPLS(const BYTE packet, MPacket *msgObj)
{ fn_decodeIPv4(packet + MPLS_PACKET_SIZE, msgObj); }

void EthernetParser::fn_decode8021Q(const BYTE packet, MPacket *msgObj)
{
	ptr_vlan_t = (struct vlan_tag*)packet;
	packetSize = sizeof(struct vlan_tag);
	type = ntohs((unsigned short int)ptr_vlan_t->vlan_tci);

	switch(type)
	{
		case ETH_IP:
					fn_decodeIPv4((const BYTE)(packet + packetSize), msgObj);
					break;
		case ETH_8021Q:
					fn_decode8021Q((const BYTE)(packet + packetSize), msgObj);
					break;
		case ETH_PPP_SES:
					fn_decodePPPoE((const BYTE)packet + packetSize, msgObj);
					break;
		default:
					break;
	}
}

void EthernetParser::fn_decodePPPoE(const BYTE packet, MPacket *msgObj)
{ fn_decodeIPv4((const BYTE)(packet + 8), msgObj); }

void EthernetParser::fn_decodeIPv4(const BYTE packet, MPacket *msgObj)
{
	 	bool dirFound	= false;
	 	bool process 	= false;

		ip4Header = (struct iphdr *)(packet);

		msgObj->ipVer 			 = ip4Header->version;

		/* Check if any Version 6 Packet inside ip Version 4 */
		if(msgObj->ipVer != IPVersion4)
		{
			msgObj->pType 	= 0;
			return;
		}

		msgObj->pType 	= ip4Header->protocol; // TCP or UDP

		switch(msgObj->pType)
		{
			case PACKET_IPPROTO_UDP:
			case PACKET_IPPROTO_TCP:
						break;
			default:
						msgObj->pType = 0;
						return;
						break;
		}

		msgObj->ipTLen 			 = ntohs((uint16_t)ip4Header->tot_len);
		msgObj->ipHLen 			 = ((unsigned int)ip4Header->ihl)*4;
		msgObj->ipIdentification = VAL_USHORT(packet + 4);
		msgObj->ipTtl 			 = ip4Header->ttl;

		abstractIpv4Address(packet, msgObj);

		msgObj->direction = getDirectionOnIPV4(msgObj->sIp, msgObj->dIp);

		if(msgObj->pType == PACKET_IPPROTO_UDP)
				getProtocolType(packet, msgObj);

		if(msgObj->direction == 0) return;

		parseNextLayer(packet + msgObj->ipHLen, msgObj);
}

void EthernetParser::abstractIpv4Address(const BYTE packet, MPacket *msgObj)
{
	uint16_t offset = 12;

	msgObj->sIp=(msgObj->sIp << 8) + (0xff & packet[offset]);
	msgObj->sIp=(msgObj->sIp << 8) + (0xff & packet[offset + 1]);
	msgObj->sIp=(msgObj->sIp << 8) + (0xff & packet[offset + 2]);
	msgObj->sIp=(msgObj->sIp << 8) + (0xff & packet[offset + 3]);

	offset += 4;

	msgObj->dIp=(msgObj->dIp << 8) + (0xff & packet[offset]);
	msgObj->dIp=(msgObj->dIp << 8) + (0xff & packet[offset + 1]);
	msgObj->dIp=(msgObj->dIp << 8) + (0xff & packet[offset + 2]);
	msgObj->dIp=(msgObj->dIp << 8) + (0xff & packet[offset + 3]);
}

bool EthernetParser::IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask)
{
    uint32_t net_lower = (network & mask);
    uint32_t net_upper = (net_lower | (~mask));

    if(ip >= net_lower && ip <= net_upper)
        return true;
    return false;
}

uint8_t EthernetParser::getDirectionOnIPV4(uint32_t &sourceIP, uint32_t &destIP)
{
	bool dirSet 		= false;
    uint16_t counter 	= 0;
    uint8_t direction 	= 0;

	for(counter = 0; counter < Global::IPV4_NO_OF_RANGE; counter++)
	{
		if(IsIPInRange(sourceIP, Global::IPV4_RANGE[counter][0], Global::IPV4_RANGE[counter][1]))
		{
			direction = UP;
			break;
		}
		else if(IsIPInRange(destIP, Global::IPV4_RANGE[counter][0], Global::IPV4_RANGE[counter][1]))
		{
			direction = DOWN;
			break;
		}
	}

	if(Global::PROCESS_OUT_OF_RANGE_IP)
	{
		if(direction == 0)
			direction = UNMAPPED;
	}

	return direction;
}

void EthernetParser::getProtocolType(const BYTE packet, MPacket *msgObj)
{
	uint16_t	sPort, dPort;
	sPort = dPort = 0;

	udpHeader = (struct udphdr *)(packet + msgObj->ipHLen);

	sPort = ntohs((unsigned short int)udpHeader->source);
	dPort = ntohs((unsigned short int)udpHeader->dest);

}

void EthernetParser::parseNextLayer(const BYTE packet, MPacket *msgObj)
{
	switch(msgObj->pType)
	{
		case PACKET_IPPROTO_TCP:
				tcp->parseTCPPacket(packet, msgObj);
				break;

		case PACKET_IPPROTO_UDP:
				udp->parseUDPPacket(packet, msgObj);
				break;

		default:
				break;
	}
}
