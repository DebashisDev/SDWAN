/*
 * TCPGlobal.h
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#ifndef INC_IPGLOBAL_H_
#define INC_IPGLOBAL_H_

#include <pthread.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <list>
#include <queue>
#include <array>
#include <bitset>

#include "SpectaTypedef.h"
#include "GConfig.h"

using namespace std;

#define UP				1
#define DOWN			2
#define UNMAPPED			3

#define UDP_HDR_LEN		8
#define PPPoE_HDR_LEN	6

#define ETH_IP        	0x0800          /* Internet Protocol packet     */
#define ETH_8021Q     	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_IPV6    	0x86DD          /* IPv6 over bluebook           */
#define ETH_MPLS_UC   	0x8847          /* MPLS Unicast traffic         */
#define ETH_PPP_SES   	0x8864          /* PPPoE session messages       */
#define ETH_ARP			0x0806			/* Address Resolution protocol  */

#define MAX_INTERFACE_SUPPORT				8
#define MAX_ROUTER_PER_INTERFACE_SUPPORT 	8

#define TCP_MAX_SESSION_MANAGER_SUPPORT 	15
#define UDP_MAX_SESSION_MANAGER_SUPPORT 	15
#define DNS_MAX_SESSION_MANAGER_SUPPORT 	10
#define UNM_MAX_SESSION_MANAGER_SUPPORT 	1

#define TCP_MAX_FLUSHER_SUPPORT				4
#define UDP_MAX_FLUSHER_SUPPORT				4
#define DNS_MAX_FLUSHER_SUPPORT				2
#define UNM_MAX_FLUSHER_SUPPORT				1

#define RADIUS_USER_NAME_LEN				33
#define MAC_ADDR_LEN						18
#define URL_LEN		 						50
#define IPV6_ADDR_LEN 						46
#define IPV4_ADDR_LEN 						16
#define MAX_RANGE_IP						32
#define XDR_MAX_LEN							32000
#define VPS_MAX_LEN							14000

#define VPS_SINGLE_ELEMENT_SIZE				30
#define MAX_CLEAN_COUNT						100000
#define CONTENT_TYPE_LEN					20
#define HTTP_AGENT_LEN						200
#define DESC_LEN							100

#define IP_XDR_ID							10
#define DNS_XDR_ID							12

#define BW_XDR_ID 							11

#define TCP_SESSION_POOL_ARRAY_ELEMENTS		100
#define TCP_SESSION_POOL_ARRAY_SIZE			1500

#define UDP_SESSION_POOL_ARRAY_ELEMENTS		100
#define UDP_SESSION_POOL_ARRAY_SIZE			1500

#define DNS_SESSION_POOL_ARRAY_ELEMENTS		100
#define DNS_SESSION_POOL_ARRAY_SIZE			1500

#define UNM_SESSION_POOL_ARRAY_ELEMENTS		100
#define UNM_SESSION_POOL_ARRAY_SIZE			1000

#define PACKET_NO							200000

#define PKT_WRITE_TIME_INDEX(epochsec,ti) (((epochsec % ti) + 1) >= ti ? 0 : ((epochsec % ti) + 1))
#define PKT_READ_TIME_INDEX(epochsec,ti) (epochsec % ti )
#define PKT_READ_NEXT_TIME_INDEX(idx,ti) ((idx+1) >= ti ? 0 : (idx+1))

typedef struct
{
  int startIp;
  int mask;
}_ipRange;

namespace ipRange
{
	extern int totalIps;
	extern _ipRange ipRange[100];
}

namespace initSection
{
	extern std::map<uint32_t, std::string> ipSubNetMap;
}


enum dnsResponse
{
	QUERY 		= 0,
	RESPONSE 	= 1,
	STATUS 		= 2,
	UNASSIGNED 	= 3,
	NOTIFY 		= 4,
	UPDATE 		= 5,
	SUCCESS		= 6
};

typedef enum
{
	PACKET_IPPROTO_HOPOPTS 	= 0,	/** IPv6 Hop-by-Hop options		*/
	PACKET_IPPROTO_ICMP 	= 1,	/** Internet Control Message Protocol */
	PACKET_IPPROTO_IGMP 	= 2,	/** Internet Group management Protocol */
	PACKET_IPPROTO_IPIP 	= 4,	/** IPIP tunnels (older KA9Q tunnels use 94) */
	PACKET_IPPROTO_TCP		= 6,	/** Transmission Control Protocol	*/
	PACLET_IPPROTO_EGP 		= 8,	/** Exterior Gateway Protocol */
	PACKET_IPPROTO_PUP 		= 12,	/** PUP Protocol */
	PACKET_IPPROTO_UDP 		= 17,	/** User Datagram Protocol		*/
	PACKET_IPPROTO_DNS 		= 18,	/** DNS		*/
	PACKET_IPPROTO_ARP 		= 19,	/** ARP		*/
	PACKET_IPPROTO_IDP 		= 22,	/** XNS IDP protocol */
	PACKET_IPPROTO_TP 		= 29,	/** SO Transport Protocol Class 4. */
	PACKET_IPPROTO_DCCP 	= 33,	/** Datagram Congestion Control Protocol. */
	PACKET_IPPROTO_IPV6 	= 41,	/** IPv6 header */
	PACKET_IPPROTO_ROUTING 	= 43,	/** IPv6 Routing header */
	PACKET_IPPROTO_FRAGMENT = 44,	/** IPv6 fragmentation header */
	PACKET_IPPROTO_RSVP 	= 46,	/** Reservation Protocol */
	PACKET_IPPROTO_GRE 		= 47,	/** General Routing Encapsulation */
	PACKET_IPPROTO_GTPU 	= 48,	/** GTPU Protocol		*/
	PACKET_IPPROTO_GTPC 	= 49,	/** GTPC Protocol		*/
	PACKET_IPPROTO_ESP 		= 50,	/** encapsulating security Payload */
	PACKET_IPPROTO_AH 		= 51,	/** Authentication header */
	PACKET_IPPROTO_GX 		= 52,	/** GTPU Protocol		*/
	PACKET_IPPROTO_RADIUS 	= 53,	/** RADIUS Protocol		*/
	PACKET_IPPROTO_ICMPV6 	= 58,	/** ICMPV6 */
	PACKET_IPPROTO_NONE 	= 59,	/** IPv6 no next header */
	PACKET_IPPROTO_DSTOPTS 	= 60,	/** IPv6 destination options */
	PACKET_IPPROTO_MTP 		= 92,	/** Multicast Transport Protocol */
	PACKET_IPPROTO_ENCAP 	= 98,	/** Encapsulation Header */
	PACKET_IPPROTO_PIM 		= 103,	/** Protocol Independent Multicast */
	PACKET_IPPROTO_COMP 	= 108,	/** Compression Header Protocol */
	PACKET_IPPROTO_SCTP 	= 132,	/** SCTP Protocol		*/
	PACKET_IPPROTO_UDPLITE 	= 136,	/** UDP-Lite protocol */
	PACKET_IPPROTO_RAW 		= 255	/** Raw IP Packets */
}IPProtocolTypes;


typedef enum{
	HTTP 		= 2,
	BW 			= 3,
	IUPS		= 21,
	SCCP		= 22,
	NONTCPUDP	= 20
}protocolId;

typedef enum {
	DNS_PORT 		= 53,
	HTTP_PORT 		= 80,
	SYSLOG_PORT		= 514,
	HTTPS_PORT 		= 443,
	GTPU_PORT 		= 2152,
	GTPC_PORT 		= 2123,
	GTPC_PORT1 		= 3386,
	HTTP_PORT1 		= 8080,
	GX_PORT			= 3868,
	RADIUS_AUTH		= 1812,
	RADIUS_ACCO 	= 1813,
	RADIUS_AUTH1	= 2812,
	RADIUS_ACCO1 	= 2813
};

typedef struct _RawPkt
{
	uint16_t	len;
	uint32_t 	tv_sec;
	uint64_t 	tv_nsec;
	BYTE		pkt;

	_RawPkt(int rawPckSize) {
		reset();
		pkt = (BYTE) malloc(rawPckSize);
	}

	_RawPkt(const _RawPkt& rpkt) {
		len 	= rpkt.len;
		tv_sec 	= rpkt.tv_sec;
		tv_nsec = rpkt.tv_nsec;
		pkt 	= rpkt.pkt;
	}

	void copy(const _RawPkt* rpkt) {
		len 	= rpkt->len;
		tv_sec 	= rpkt->tv_sec;
		tv_nsec = rpkt->tv_nsec;
		pkt 	= rpkt->pkt;
	}

	void operator=(const _RawPkt& rpkt) {
		len 	= rpkt.len;
		tv_sec 	= rpkt.tv_sec;
		tv_nsec = rpkt.tv_nsec;
		pkt 	= rpkt.pkt;
	}

	void reset() {
		len = 0;
		tv_sec = 0;
		tv_nsec = 0;
	}

}RawPkt;

typedef struct _MPacket
{
	uint8_t 	ipVer;
	uint8_t 	ipTtl;
	uint8_t		direction;
	uint8_t		pType;
	uint8_t		qrFlag;
	uint8_t		responseCode;
	char 		sIpv6[IPV6_ADDR_LEN];
	char		dIpv6[IPV6_ADDR_LEN];
	char 		sMac[MAC_ADDR_LEN];
	char		dMac[MAC_ADDR_LEN];
	char 		url[URL_LEN];
	char		replyMsg[35];
	char		resolvedIp[IPV6_ADDR_LEN];
	uint16_t	frSize;
	uint16_t 	ipTLen;
	uint16_t 	ipHLen;
	uint16_t	ipIdentification;
	uint16_t 	sPort;
	uint16_t 	dPort;
	uint16_t	pLoad;
	uint16_t	tcpFlags;
	uint32_t 	sIp;
	uint32_t	dIp;
	uint32_t 	tcpSeqNo;
	uint32_t	transactionId;
	uint32_t	inputOctets;
	uint32_t	outputOctets;
	uint32_t	inputGigaWords;
	uint32_t	outputGigaWords;
	uint32_t	inputPackets;
	uint32_t	outputPackets;
	uint64_t	frTimeEpochSec;
	uint64_t	ipv4FlowId;
	uint64_t	frTimeEpochNanoSec;
	uint64_t    frTimeEpochMilliSec;

	_MPacket()
	{ reset(); }

	_MPacket(const _MPacket& mpkt)
	{
		this->ipVer				= mpkt.ipVer;
		this->ipTtl				= mpkt.ipTLen;
		this->direction 		= mpkt.direction;
		this->pType				= mpkt.pType;
		this->qrFlag			= mpkt.qrFlag;
		this->responseCode		= mpkt.responseCode;
		strcpy(this->sIpv6, mpkt.sIpv6);
		strcpy(this->dIpv6, mpkt.dIpv6);
		strcpy(this->sMac, mpkt.sMac);
		strcpy(this->dMac, mpkt.dMac);
		strcpy(this->url, mpkt.url);
		strcpy(this->replyMsg, mpkt.replyMsg);
		strcpy(this->resolvedIp, mpkt.resolvedIp);
		this->frSize			= mpkt.frSize;
		this->ipTLen			= mpkt.ipTLen;
		this->ipHLen			= mpkt.ipHLen;
		this->ipIdentification 	= mpkt.ipIdentification;
		this->sPort				= mpkt.sPort;
		this->dPort				= mpkt.dPort;
		this->pLoad				= mpkt.pLoad;
		this->tcpFlags			= mpkt.tcpFlags;
		this->sIp				= mpkt.sIp;
		this->dIp				= mpkt.dIp;
		this->tcpSeqNo			= mpkt.tcpSeqNo;
		this->transactionId		= mpkt.transactionId;
		this->inputOctets		= mpkt.inputOctets;
		this->outputOctets		= mpkt.outputOctets;
		this->inputGigaWords	= mpkt.inputGigaWords;
		this->outputGigaWords	= mpkt.outputGigaWords;
		this->inputPackets		= mpkt.inputPackets;
		this->outputPackets		= mpkt.outputPackets;
		this->frTimeEpochSec	= mpkt.frTimeEpochSec;
		this->ipv4FlowId		= mpkt.ipv4FlowId;
		this->frTimeEpochNanoSec= mpkt.frTimeEpochNanoSec;
		this->frTimeEpochMilliSec= mpkt.frTimeEpochMilliSec;
	}

	void copy(const _MPacket* mpkt)
	{
		this->ipVer				= mpkt->ipVer;
		this->ipTtl				= mpkt->ipTLen;
		this->direction 		= mpkt->direction;
		this->pType				= mpkt->pType;
		this->qrFlag			= mpkt->qrFlag;
		this->responseCode		= mpkt->responseCode;
		strcpy(this->sIpv6, mpkt->sIpv6);
		strcpy(this->dIpv6, mpkt->dIpv6);
		strcpy(this->sMac, mpkt->sMac);
		strcpy(this->dMac, mpkt->dMac);
		strcpy(this->url, mpkt->url);
		strcpy(this->replyMsg, mpkt->replyMsg);
		strcpy(this->resolvedIp, mpkt->resolvedIp);
		this->frSize			= mpkt->frSize;
		this->ipTLen			= mpkt->ipTLen;
		this->ipHLen			= mpkt->ipHLen;
		this->ipIdentification 	= mpkt->ipIdentification;
		this->sPort				= mpkt->sPort;
		this->dPort				= mpkt->dPort;
		this->pLoad				= mpkt->pLoad;
		this->tcpFlags			= mpkt->tcpFlags;
		this->sIp				= mpkt->sIp;
		this->dIp				= mpkt->dIp;
		this->tcpSeqNo			= mpkt->tcpSeqNo;
		this->transactionId		= mpkt->transactionId;
		this->inputOctets		= mpkt->inputOctets;
		this->outputOctets		= mpkt->outputOctets;
		this->inputGigaWords	= mpkt->inputGigaWords;
		this->outputGigaWords	= mpkt->outputGigaWords;
		this->inputPackets		= mpkt->inputPackets;
		this->outputPackets		= mpkt->outputPackets;
		this->frTimeEpochSec	= mpkt->frTimeEpochSec;
		this->ipv4FlowId		= mpkt->ipv4FlowId;
		this->frTimeEpochNanoSec= mpkt->frTimeEpochNanoSec;
		this->frTimeEpochMilliSec= mpkt->frTimeEpochMilliSec;
	}

	void reset()
	{
		this->ipVer				= 0;
		this->ipTtl				= 0;
		this->direction 		= 0;
		this->pType				= 0;
		this->qrFlag			= 3;				/* Default is 3, 0 - Request, 1 - Response */
		this->responseCode		= 3;
		this->sIpv6[0]			= 0;
		this->dIpv6[0]			= 0;
		this->sMac[0]			= 0;
		this->dMac[0]			= 0;
		this->url[0]			= 0;
		strcpy(this->replyMsg, "NA");
		this->resolvedIp[0] 	= 0;
		this->frSize			= 0;
		this->ipTLen			= 0;
		this->ipHLen			= 0;
		this->ipIdentification 	= 0;
		this->sPort				= 0;
		this->dPort				= 0;
		this->pLoad				= 0;
		this->tcpFlags			= 0;
		this->sIp				= 0;
		this->dIp				= 0;
		this->tcpSeqNo			= 0;
		this->transactionId		= 0;
		this->inputOctets		= 0;
		this->outputOctets		= 0;
		this->inputGigaWords	= 0;
		this->outputGigaWords	= 0;
		this->inputPackets		= 0;
		this->outputPackets		= 0;
		this->frTimeEpochSec	= 0;
		this->ipv4FlowId		= 0;
		this->frTimeEpochNanoSec= 0;
		this->frTimeEpochMilliSec= 0;
	}
}MPacket;

typedef struct _bwData
{
	uint64_t Bw;
	uint64_t upBw;
	uint64_t dnBw;

	uint64_t totalVol;
	uint64_t upTotalVol;
	uint64_t dnTotalVol;
	uint64_t avgTotalBw;
	uint64_t avgUpBw;
	uint64_t avgDnBw;
	uint64_t peakTotalVol;
	uint64_t peakUpTotalVol;
	uint64_t peakDnTotalVol;

	_bwData()
	{
		Bw 				= 0;
		upBw 			= 0;
		dnBw 			= 0;
		totalVol 		= 0;
		upTotalVol 		= 0;
		dnTotalVol 		= 0;
		avgTotalBw 		= 0;
		avgUpBw 		= 0;
		avgDnBw 		= 0;
		peakTotalVol 	= 0;
		peakUpTotalVol 	= 0;
		peakDnTotalVol 	= 0;
	}
}bwData;

typedef struct _cdnData
{
	uint64_t Bw;
	uint64_t upBw;
	uint64_t dnBw;

	uint64_t totalVol;
	uint64_t upTotalVol;
	uint64_t dnTotalVol;
	uint64_t avgTotalBw;
	uint64_t avgUpBw;
	uint64_t avgDnBw;
	uint64_t peakTotalVol;
	uint64_t peakUpTotalVol;
	uint64_t peakDnTotalVol;

	_cdnData()
	{
		Bw 				= 0;
		upBw 			= 0;
		dnBw 			= 0;
		totalVol 		= 0;
		upTotalVol 		= 0;
		dnTotalVol 		= 0;
		avgTotalBw 		= 0;
		avgUpBw 		= 0;
		avgDnBw 		= 0;
		peakTotalVol 	= 0;
		peakUpTotalVol 	= 0;
		peakDnTotalVol 	= 0;
	}
}cdnData;

namespace Global
{
	extern uint16_t 	LOG_LEVEL;
	extern uint16_t		OPERATOR_ID;
	extern std::string 	XDR_DIR, UNKNOWN_XDR_DIR, LOG_DIR, DATA_DIR;

	/* Received Packet Count */
	extern uint64_t		TCP_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	extern uint64_t		UDP_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	extern uint64_t		DNS_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

	extern uint64_t		SM_TCP_PACKETS_PER_DAY[TCP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint64_t		SM_UDP_PACKETS_PER_DAY[UDP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint64_t		SM_DNS_PACKETS_PER_DAY[DNS_MAX_SESSION_MANAGER_SUPPORT];
	extern uint64_t		SM_UN_PACKETS_PER_DAY[UNM_MAX_SESSION_MANAGER_SUPPORT];

	/* Time to Cleanup Session */
	extern uint16_t		END_OF_DAY_CLEAN_HOUR;
	extern uint16_t		END_OF_DAY_CLEAN_MIN;
	extern uint16_t		END_OF_DAY_CLEAN_SEC;

	/* Timer Parameters */
	extern uint16_t		CURRENT_SEC;
	extern uint16_t		CURRENT_HOUR;
	extern uint16_t		CURRENT_MIN;
	extern uint16_t		CURRENT_DAY;
	extern uint16_t		CURRENT_MONTH;
	extern uint16_t		CURRENT_YEAR;
	extern uint64_t		CURRENT_EPOCH_SEC;
	extern uint64_t		CURRENT_EPOCH_MICRO_SEC;
	extern uint64_t 	CURRENT_EPOCH_NANO_SEC;
	extern uint64_t 	CURRENT_EPOCH_MILI_SEC;

	/* IP Range Parameters */
	extern uint16_t			IPV4_NO_OF_RANGE;
	extern uint32_t			IPV4_RANGE[MAX_RANGE_IP][2];

	/* Log Status */
	extern bool 		PRINT_STATS;
	extern bool			PROBE_STATS_RUNNING_STATUS;
	extern uint16_t 	PROBE_ID;
	extern uint16_t 	PRINT_STATS_FREQ_SEC;
	extern uint16_t		LOG_STATS_FREQ_SEC;

	/* Interface Parameters */
	extern bool			PKT_LISTENER_DAYCHANGE_INDICATION[MAX_INTERFACE_SUPPORT];
	extern bool			PKT_LISTENER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	extern bool			PKT_LISTENER_INTF_MON_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	extern uint16_t		NO_OF_NIC_INTERFACE;
	extern uint16_t 	NO_OF_INTERFACES;
	extern uint16_t		PKT_LISTENER_CPU_CORE[MAX_INTERFACE_SUPPORT];
	extern uint16_t		PPS_CAP_PERCENTAGE[MAX_INTERFACE_SUPPORT];
	extern uint16_t		MAX_PKT_LEN_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint32_t 	PPS_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern	string 		ETHERNET_INTERFACES[MAX_INTERFACE_SUPPORT];
	extern	string		PNAME[MAX_INTERFACE_SUPPORT];

	/* Router Parameters */
	extern bool			PKT_ROUTER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	extern uint16_t		NO_OF_ROUTERS;
	extern uint16_t 	ROUTER_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint16_t 	PKT_ROUTER_CPU_CORE[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

	/* Bandwidth Parameters */
	extern uint16_t		MAX_BW_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint32_t 	PKT_RATE_INTF[MAX_INTERFACE_SUPPORT];
	extern uint64_t 	PKTS_TOTAL_INTF[MAX_INTERFACE_SUPPORT];
	extern uint64_t 	BW_MBPS_INTF[MAX_INTERFACE_SUPPORT];
	extern bwData 		BW_MBPS_i_r[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	extern cdnData 		CDN_MBPS_i_r[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

	/* Probe Parameters */
	extern bool			PROBE_RUNNING_STATUS;
	extern bool			PROCESS_OUT_OF_RANGE_IP;
	extern bool			PACKET_PROCESSING[MAX_INTERFACE_SUPPORT];
	extern bool			ADMIN_FLAG;
	extern uint16_t		TIMER_CPU_CORE;
	extern uint16_t		DNS_DUMP_HOUR;
	extern uint16_t		TIME_INDEX;
	extern uint16_t		SLEEP_TIME;
    extern uint64_t 	DISCARDED_PACKETS[MAX_INTERFACE_SUPPORT];
	extern string		ADMIN_PORT;

	/* TCP / UDP / DNS Session Manager Parameters */
	extern bool 		UDP_XDR_FOR_DNS;
	extern bool			CHECK_DUPLICATE;
	extern bool 		PROCESS_ACK;
	extern bool			ACK_CREATE_SESSION;
	extern bool			PROCESS_USER_AGENT;

	extern bool			TCP_SESSION_MANAGER_RUNNING_STATUS[TCP_MAX_SESSION_MANAGER_SUPPORT];
	extern bool			UDP_SESSION_MANAGER_RUNNING_STATUS[UDP_MAX_SESSION_MANAGER_SUPPORT];
	extern bool			DNS_SESSION_MANAGER_RUNNING_STATUS[DNS_MAX_SESSION_MANAGER_SUPPORT];
	extern bool			UNM_SESSION_MANAGER_RUNNING_STATUS[UNM_MAX_SESSION_MANAGER_SUPPORT];

	extern bool			TCP_FLUSHER_RUNNING_STATUS[TCP_MAX_FLUSHER_SUPPORT];
	extern bool			UDP_FLUSHER_RUNNING_STATUS[UDP_MAX_FLUSHER_SUPPORT];
	extern bool			DNS_FLUSHER_RUNNING_STATUS[DNS_MAX_FLUSHER_SUPPORT];
	extern bool			UNM_FLUSHER_RUNNING_STATUS[UNM_MAX_FLUSHER_SUPPORT];

	extern bool			IP_WRITE_XDR;
	extern bool			DNS_WRITE_XDR;
	extern bool			UNM_WRITE_XDR;

	extern uint16_t 	NO_OF_TCP_FLUSHER;
	extern uint16_t 	TCP_SESSION_MANAGER_INSTANCES;
	extern uint16_t 	TCP_SESSION_MANAGER_CPU_CORE[TCP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint16_t 	NO_OF_UDP_FLUSHER;
	extern uint16_t		UDP_SESSION_MANAGER_INSTANCES;
	extern uint16_t		UDP_SESSION_MANAGER_CPU_CORE[UDP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint16_t 	NO_OF_DNS_FLUSHER;
	extern uint16_t		DNS_SESSION_MANAGER_INSTANCES;
	extern uint16_t		DNS_SESSION_MANAGER_CPU_CORE[DNS_MAX_SESSION_MANAGER_SUPPORT];

	extern uint16_t 	NO_OF_UNM_FLUSHER;
	extern uint16_t		UNM_SESSION_MANAGER_INSTANCES;
	extern uint16_t		UNMAPPED_SESSION_MANAGER_CPU_CORE[UNM_MAX_SESSION_MANAGER_SUPPORT];

	extern uint16_t		TCP_FLUSHER_CPU_CORE[TCP_MAX_FLUSHER_SUPPORT];
	extern uint16_t		UDP_FLUSHER_CPU_CORE[UDP_MAX_FLUSHER_SUPPORT];
	extern uint16_t		DNS_FLUSHER_CPU_CORE[DNS_MAX_FLUSHER_SUPPORT];
	extern uint16_t		UNM_FLUSHER_CPU_CORE[UNM_MAX_FLUSHER_SUPPORT];

	extern uint16_t 	DNS_ANSWER;
	extern uint16_t		VPS_PACKET_PER_SEC;
	extern uint16_t 	SESSION_TIME_LIMIT;
	extern uint16_t 	SESSION_PKT_LIMIT;
	extern uint16_t 	IP_SESSION_CLEAN_UP_TIMEOUT_SEC;
	extern uint16_t 	DNS_SESSION_CLEAN_UP_TIMEOUT_SEC;
	extern uint16_t 	IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	extern uint16_t 	MAX_TCP_SIZE;
	extern uint32_t		SM_PKT_LIMIT;
}

namespace IPStats
{
	extern uint64_t dnsLookupMapSize;

	extern uint32_t smTcpV4SessionCnt[TCP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smTcpV6SessionCnt[TCP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smTcpV4SessionScan[TCP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smTcpV6SessionScan[TCP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smTcpV4SessionClean[TCP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smTcpV6SessionClean[TCP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUdpV4SessionCnt[UDP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUdpV6SessionCnt[UDP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUdpV4SessionScan[UDP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUdpV6SessionScan[UDP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUdpV4SessionClean[UDP_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUdpV6SessionClean[UDP_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smDnsV4SessionCnt[DNS_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smDnsV6SessionCnt[DNS_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smDnsV4SessionScan[DNS_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smDnsV6SessionScan[DNS_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smDnsV4SessionClean[DNS_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smDnsV6SessionClean[DNS_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUnTcpSessionCnt[UNM_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUnUdpSessionCnt[UNM_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUnTcpSessionScan[UNM_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUnUdpSessionScan[UNM_MAX_SESSION_MANAGER_SUPPORT];

	extern uint32_t smUnTcpSessionClean[UNM_MAX_SESSION_MANAGER_SUPPORT];
	extern uint32_t smUnUdpSessionClean[UNM_MAX_SESSION_MANAGER_SUPPORT];

}

namespace PKTStore
{
	extern std::unordered_map<uint32_t, RawPkt*> store[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t cnt[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool busy[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace initalize
{
	extern std::map<uint16_t, std::string> protocolName;
	extern std::map<uint16_t, std::string> dnsErrorCode;
	extern std::map<uint16_t, std::string> tcpPorts;
	extern std::map<uint16_t, std::string> radiusCodeMap;
	extern std::map<uint16_t, std::string> serviceTypeMap;
	extern std::map<uint16_t, std::string> framedProtocolMap;
	extern std::map<uint16_t, std::string> acctAuthenticMap;
	extern std::map<uint16_t, std::string> acctTeminateMap;
	extern std::map<uint16_t, std::string> acctStatusMap;
	extern std::map<uint16_t, std::string> nasPortTypeMap;
}

namespace SmStore
{
	extern std::unordered_map<uint32_t, MPacket> tcpStore[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool tcpBusy[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t tcpCnt[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	extern std::unordered_map<uint32_t, MPacket> udpStore[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool udpBusy[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t udpCnt[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	extern std::unordered_map<uint32_t, MPacket> dnsStore[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool dnsBusy[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t dnsCnt[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	extern std::unordered_map<uint32_t, MPacket> unStore[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool unBusy[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t unCnt[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

}

namespace mapDnsLock
{
	extern pthread_mutex_t lockCount;
	extern pthread_cond_t nonzero;
	extern unsigned count;
}

class IPGlobal
{
	public:
		IPGlobal();
		~IPGlobal();

		static void initProtocolName();
		static void dnsErrorCode();
		static void tcpPorts();
};

#endif /* INC_IPGLOBAL_H_ */
