/*
 * EthernetProbe.h
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_ETHERNETPARSER_H_
#define CORE_SRC_ETHERNETPARSER_H_

#include <string.h>
#include <algorithm>
#include <stdlib.h>    //malloc

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <pcap/vlan.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

#include "Log.h"
#include "BaseConfig.h"
#include "IPGlobal.h"
#include "tcpParser.h"
#include "udpParser.h"
#include "ProbeUtility.h"

#define ETH_P_MPLS 			34887
#define MPLS_PACKET_SIZE 	4
#define IPV6_HEADER_LEN		40
#define IPV6_STRSIZE 		46
#define BASE 				16

class EthernetParser : public BaseConfig
{
	private:

		tcpParser*		tcp;
		udpParser*		udp;
		ProbeUtility*	pUt;

		uint16_t 		type;
		uint16_t 		ethOffset;
		uint16_t 		interfaceId;
		uint16_t 		routerId;
		uint16_t 		packetSize;

		struct vlan_tag *ptr_vlan_t;

		struct iphdr*		ip4Header;
		struct ip6_hdr*  	ip6Header;
		struct udphdr*		udpHeader;

		bool		IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask);
		void		parseNextLayer(const BYTE packet, MPacket *msgObj);
		void		getProtocolType(const BYTE packet, MPacket *msgObj);
		void		getGxProtocolType(const BYTE packet, MPacket *msgObj);
		void		generateKey(MPacket *msgObj);
		void   		hexDump(const void* pv, uint16_t len);
		uint8_t		getDirectionOnIPV4(uint32_t &sourceIP, uint32_t &destIP);
		uint8_t		getDirectionOnIPV6(char *sourceIP, char *destIP);

		void		fn_decodeIPv4(const BYTE packet, MPacket *msgObj);
		void		fn_decode8021Q(const BYTE packet, MPacket *msgObj);
		void		fn_decodeIPv6(const BYTE packet, MPacket *msgObj);
		void		fn_decodePPPoE(const BYTE packet, MPacket *msgObj);
		void		fn_decodeMPLS(const BYTE packet, MPacket *msgObj);

		void		abstractIpv4Address(const BYTE packet, MPacket *msgObj);
		void		abstractIpv6Address(const BYTE packet, MPacket *msgObj);

	public:
		EthernetParser(uint16_t intfid, uint16_t rId);
		~EthernetParser();

		void 	parsePacket(const BYTE packet, MPacket *msgObj);
};

#endif /* CORE_SRC_ETHERNETPARSER_H_ */
