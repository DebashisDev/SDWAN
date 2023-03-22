/*
 * TCPGlobal.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#include "IPGlobal.h"

using namespace std;

namespace ipRange
{
	int totalIps;
	_ipRange ipRange[100];
}

namespace initSection
{
	std::map<uint32_t, std::string> ipSubNetMap;
}

namespace IPStats
{
	uint64_t dnsLookupMapSize 	= 0;

	uint32_t smTcpV4SessionCnt[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smTcpV6SessionCnt[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smTcpV4SessionScan[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smTcpV6SessionScan[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smTcpV4SessionClean[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smTcpV6SessionClean[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUdpV4SessionCnt[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUdpV6SessionCnt[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUdpV4SessionScan[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUdpV6SessionScan[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUdpV4SessionClean[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUdpV6SessionClean[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smDnsV4SessionCnt[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smDnsV6SessionCnt[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smDnsV4SessionScan[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smDnsV6SessionScan[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smDnsV4SessionClean[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smDnsV6SessionClean[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUnTcpSessionCnt[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUnUdpSessionCnt[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUnTcpSessionScan[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUnUdpSessionScan[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint32_t smUnTcpSessionClean[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint32_t smUnUdpSessionClean[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};


}

namespace PKTStore
{
	std::unordered_map<uint32_t, RawPkt*> store[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t cnt[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool busy[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace SmStore
{
	std::unordered_map<uint32_t, MPacket> tcpStore[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool tcpBusy[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t tcpCnt[TCP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	std::unordered_map<uint32_t, MPacket> udpStore[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool udpBusy[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t udpCnt[UDP_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	std::unordered_map<uint32_t, MPacket> dnsStore[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool dnsBusy[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t dnsCnt[DNS_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

	std::unordered_map<uint32_t, MPacket> unStore[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool unBusy[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t unCnt[UNM_MAX_SESSION_MANAGER_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];

}
namespace Global
{
	uint16_t 		LOG_LEVEL;
	uint16_t		OPERATOR_ID;
	std::string 	XDR_DIR, UNKNOWN_XDR_DIR, LOG_DIR, DATA_DIR;

	/* Received Packet Count */
	uint64_t	TCP_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};
	uint64_t	UDP_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};
	uint64_t	DNS_PACKETS_PER_DAY[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};

	uint64_t	SM_TCP_PACKETS_PER_DAY[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint64_t	SM_UDP_PACKETS_PER_DAY[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint64_t	SM_DNS_PACKETS_PER_DAY[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};
	uint64_t	SM_UN_PACKETS_PER_DAY[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};


	/* Time to Cleanup Session */
	uint16_t	END_OF_DAY_CLEAN_HOUR	= 23;
	uint16_t	END_OF_DAY_CLEAN_MIN	= 59;
	uint16_t	END_OF_DAY_CLEAN_SEC	= 30;

	/* Timer Parameters */
	uint16_t	CURRENT_SEC 			= 0;
	uint16_t	CURRENT_HOUR 			= 0;
	uint16_t	CURRENT_MIN 			= 0;
	uint16_t	CURRENT_DAY 			= 0;
	uint16_t	CURRENT_MONTH 			= 0;
	uint16_t	CURRENT_YEAR			= 0;
	uint64_t	CURRENT_EPOCH_SEC 		= 0;
	uint64_t	CURRENT_EPOCH_MICRO_SEC = 0;
	uint64_t 	CURRENT_EPOCH_NANO_SEC 	= 0;
	uint64_t 	CURRENT_EPOCH_MILI_SEC 	= 0;

	/* IP Range Parameters */
	uint16_t	IPV4_NO_OF_RANGE = 0;
	uint32_t	IPV4_RANGE[MAX_RANGE_IP][2]	= {{0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}};

	/* Log Status */
	bool 		PRINT_STATS = false;
	bool		PROBE_STATS_RUNNING_STATUS = true;
	uint16_t 	PROBE_ID = 10;
	uint16_t 	PRINT_STATS_FREQ_SEC = 1;
	uint16_t	LOG_STATS_FREQ_SEC = 1;

	/* Interface Parameters */
	bool		PKT_LISTENER_DAYCHANGE_INDICATION[MAX_INTERFACE_SUPPORT] = {false};
	bool		PKT_LISTENER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	bool		PKT_LISTENER_INTF_MON_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	uint16_t	NO_OF_NIC_INTERFACE = 0;
	uint16_t 	NO_OF_INTERFACES = 0;
	uint16_t	PKT_LISTENER_CPU_CORE[MAX_INTERFACE_SUPPORT] = {0};
	uint16_t	PPS_CAP_PERCENTAGE[MAX_INTERFACE_SUPPORT]	= {50,50,50,50,50,50,50,50};
	uint16_t	MAX_PKT_LEN_PER_INTERFACE[MAX_INTERFACE_SUPPORT] = {0};
	uint32_t 	PPS_PER_INTERFACE[MAX_INTERFACE_SUPPORT] 	= {500000,500000,500000,500000,500000,500000,500000,500000};
	string 		ETHERNET_INTERFACES[MAX_INTERFACE_SUPPORT] 		= {""};
	string 		PNAME[MAX_INTERFACE_SUPPORT] = {""};

	/* Router Parameters */
	bool		PKT_ROUTER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	uint16_t	NO_OF_ROUTERS = 0;
	uint16_t 	ROUTER_PER_INTERFACE[MAX_INTERFACE_SUPPORT] 	= {0};
	uint16_t	PKT_ROUTER_CPU_CORE[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};

	/* Bandwidth Parameters */
	uint16_t 	MAX_BW_INTERFACE[MAX_INTERFACE_SUPPORT]			= {0};
	uint32_t 	PKT_RATE_INTF[MAX_INTERFACE_SUPPORT] = {0};
	uint64_t	PKTS_TOTAL_INTF[MAX_INTERFACE_SUPPORT] = {0};
	uint64_t 	BW_MBPS_INTF[MAX_INTERFACE_SUPPORT] = {0};
	bwData 		BW_MBPS_i_r[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	cdnData 	CDN_MBPS_i_r[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

	/* Probe Parameters */
	bool		PROBE_RUNNING_STATUS 						= false;
	bool		PROCESS_OUT_OF_RANGE_IP						= false;
	bool		PACKET_PROCESSING[MAX_INTERFACE_SUPPORT] 	= {false, false, false, false, false, false, false, false};
	bool		ADMIN_FLAG 									= false;
	uint16_t	TIMER_CPU_CORE								= 0;
	uint16_t	DNS_DUMP_HOUR 								= 4;
	uint16_t	TIME_INDEX 									= 10;
	uint16_t	SLEEP_TIME									= 25000;
	uint64_t 	DISCARDED_PACKETS[MAX_INTERFACE_SUPPORT]	= {0};
	string		ADMIN_PORT;

	/* TCP / UDP / DNS Session Manager Parameters */
	bool 		UDP_XDR_FOR_DNS 							= false;
	bool		CHECK_DUPLICATE 							= true;
	bool		PROCESS_ACK									= true;
	bool		ACK_CREATE_SESSION 							= true;
	bool		PROCESS_USER_AGENT							= false;

	bool		TCP_SESSION_MANAGER_RUNNING_STATUS[TCP_MAX_SESSION_MANAGER_SUPPORT];
	bool		UDP_SESSION_MANAGER_RUNNING_STATUS[UDP_MAX_SESSION_MANAGER_SUPPORT];
	bool		DNS_SESSION_MANAGER_RUNNING_STATUS[DNS_MAX_SESSION_MANAGER_SUPPORT];
	bool		UNM_SESSION_MANAGER_RUNNING_STATUS[UNM_MAX_SESSION_MANAGER_SUPPORT];

	bool		TCP_FLUSHER_RUNNING_STATUS[TCP_MAX_FLUSHER_SUPPORT];
	bool		UDP_FLUSHER_RUNNING_STATUS[UDP_MAX_FLUSHER_SUPPORT];
	bool		DNS_FLUSHER_RUNNING_STATUS[DNS_MAX_FLUSHER_SUPPORT];
	bool		UNM_FLUSHER_RUNNING_STATUS[UNM_MAX_FLUSHER_SUPPORT];

	bool		IP_WRITE_XDR 								= false;
	bool		DNS_WRITE_XDR 								= false;
	bool		UNM_WRITE_XDR 								= false;

	uint16_t	NO_OF_TCP_FLUSHER 							= 0;
	uint16_t	TCP_SESSION_MANAGER_INSTANCES 					= 0;
	uint16_t	TCP_SESSION_MANAGER_CPU_CORE[TCP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint16_t	NO_OF_UDP_FLUSHER 							= 0;
	uint16_t	UDP_SESSION_MANAGER_INSTANCES 					= 0;
	uint16_t	UDP_SESSION_MANAGER_CPU_CORE[UDP_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint16_t	NO_OF_DNS_FLUSHER 							= 0;
	uint16_t	DNS_SESSION_MANAGER_INSTANCES 					= 0;
	uint16_t	DNS_SESSION_MANAGER_CPU_CORE[DNS_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint16_t	NO_OF_UNM_FLUSHER 							= 0;
	uint16_t	UNM_SESSION_MANAGER_INSTANCES 					= 0;
	uint16_t	UNMAPPED_SESSION_MANAGER_CPU_CORE[UNM_MAX_SESSION_MANAGER_SUPPORT] = {0};

	uint16_t	TCP_FLUSHER_CPU_CORE[TCP_MAX_FLUSHER_SUPPORT] 	= {0};
	uint16_t	DNS_FLUSHER_CPU_CORE[DNS_MAX_FLUSHER_SUPPORT] 	= {0};
	uint16_t	UDP_FLUSHER_CPU_CORE[UDP_MAX_FLUSHER_SUPPORT] 	= {0};
	uint16_t	UNM_FLUSHER_CPU_CORE[UNM_MAX_FLUSHER_SUPPORT] 	= {0};

	uint16_t	DNS_ANSWER									= 5;
	uint16_t	VPS_PACKET_PER_SEC							= 1000;
	uint16_t 	SESSION_TIME_LIMIT 						= 900;
	uint16_t 	SESSION_PKT_LIMIT 						= 0;
	uint16_t	IP_SESSION_CLEAN_UP_TIMEOUT_SEC 			= 120;
	uint16_t	DNS_SESSION_CLEAN_UP_TIMEOUT_SEC 			= 120;
	uint16_t 	IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC 			= 15;
	uint16_t 	MAX_TCP_SIZE 								= 3000;
	uint32_t	SM_PKT_LIMIT								= 0;
}

namespace initalize
{
	std::map<uint16_t, std::string> protocolName;
	std::map<uint16_t, std::string> dnsErrorCode;
	std::map<uint16_t, std::string> tcpPorts;
	std::map<uint16_t, std::string> radiusCodeMap;
	std::map<uint16_t, std::string> serviceTypeMap;
	std::map<uint16_t, std::string> framedProtocolMap;
	std::map<uint16_t, std::string> acctAuthenticMap;
	std::map<uint16_t, std::string> acctTeminateMap;
	std::map<uint16_t, std::string> acctStatusMap;
	std::map<uint16_t, std::string> nasPortTypeMap;
}


namespace mapDnsLock
{
	pthread_mutex_t lockCount = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t nonzero = PTHREAD_COND_INITIALIZER;
	unsigned count;
}

IPGlobal::IPGlobal()
{ initProtocolName(); }

IPGlobal::~IPGlobal()
{ }

void IPGlobal::initProtocolName()
{
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(6, "TCP"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(17, "UDP"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(1812, "RADIUS-AUTH"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(2812, "RADIUS-AUTH"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(31812, "RADIUS-AUTH"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(1813, "RADIUS-ACCO"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(2813, "RADIUS-ACCO"));
	initalize::protocolName.insert(std::pair<uint16_t, std::string>(31813, "RADIUS-ACCO"));
}

void IPGlobal::dnsErrorCode()
{
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(0, "No Error"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(1, "Format Error"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(2, "Server Failure"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(3, "No Such Name"));	/* Non-Existent Domain Name */
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(4, "Not Implemented"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(5, "Query Refused"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(6, "Name Exists when it should not"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(7, "RR Set Exists when it should not"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(8, "RR Set that should exist does not"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(9, "Server Not Authoritative for zone"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(10, "Name not contained in zone"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(11, "UNASSIGNED"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(12, "UNASSIGNED"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(13, "UNASSIGNED"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(14, "UNASSIGNED"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(15, "UNASSIGNED"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(16, "Bad OPT Version"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(17, "Key not recognized"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(18, "Signature out of time window"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(19, "Bad TKEY Mode"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(20, "Duplicate key name"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(21, "Algorithm not supported"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(22, "Bad Truncation"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(23, "Bad/missing server cookie"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(24, "Bad Address"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(25, "No Answer Count"));
	initalize::dnsErrorCode.insert(std::pair<uint16_t, std::string>(26, "Name Server"));
}

void IPGlobal::tcpPorts()
{
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(1, "TCPMUX"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(5, "Remote Job Entry"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(7, "ECHO"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(18, "Message Send Protocol"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(20, "FTP-Data"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(21, "FTP-Control"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(22, "SSH"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(23, "TELNET"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(25, "SMTP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(29, "MSG ICP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(37, "Time"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(42, "Host Name Server"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(43, "WhoIs"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(53, "DNS"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(69, "TFTP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(70, "Gopher Services"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(79, "Finger"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(80, "HTTP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(103, "X.400 Standard"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(108, "SNA Gateway Access Server"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(109, "POP2"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(110, "POP3"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(115, "SFTP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(118, "SQL Services"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(119, "Newsgroup"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(137, "NetBIOS Name Service"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(139, "NetBIOS Datagram Service"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(143, "IMAP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(150, "NetBIOS Session Service"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(156, "SQL Server"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(161, "SNMP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(179, "Border Gateway Protocol"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(190, "GACP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(194, "Internet Relay Chat"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(197, "DLS"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(389, "LDAP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(396, "Novell Netware over IP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(443, "HTTPS"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(444, "SNPP"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(445, "Microsoft-DS"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(458, "Apple QuickTime"));
	initalize::tcpPorts.insert(std::pair<uint16_t, std::string>(546, "DHCP Client"));
}

