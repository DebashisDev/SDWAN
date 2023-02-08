/*
 * TCPUDPGlobal.h
 *
 *  Created on: 15-Jul-2016
 *      Author: Debashis
 */

#ifndef PLUGINS_TCP_INC_SMGLOBAL_H_
#define PLUGINS_TCP_INC_SMGLOBAL_H_


#include <map>
#include <unordered_map>

#include "IPGlobal.h"
#include "SpectaTypedef.h"

using namespace std;

#define DNS_HDR_LEN		12
#define	STUN_PORT		3478
#define UDP_NO_ERROR	0

#define IP_POOL_ARRAY_ELEMENTS			100		//Poosible values 10, 100, 1000, 10000, 100000....

#define IP_FLUSH_POOL_ARRAY_ELEMENTS	100		//Poosible values 10, 100, 1000, 10000, 100000....
#define IP_FLUSH_POOL_ARRAY_SIZE		5000

#define DNS_FLUSH_POOL_ARRAY_ELEMENTS	100		//Poosible values 10, 100, 1000, 10000, 100000....
#define DNS_FLUSH_POOL_ARRAY_SIZE		3000

#define DIAMETER_SEQ_ID	263

typedef enum {
    CHANGE_CIPHER_SPEC 	= 20,
	ALERT 				= 21,
	HANDSHAKE 			= 22,
    APP_DATA 			= 23
}TLSContentType;

typedef struct _dnsV6Url{
	int		pckLastTimeEpcohSec;
	char 	URL[URL_LEN];
	char 	address[IPV6_ADDR_LEN];

	_dnsV6Url()
	{
		pckLastTimeEpcohSec = 0;
		URL[0] = 0;
		address[0] = 0;
	}
}dnsV6Url;

typedef struct _dnsSession
{
	uint8_t		ipVer;
	uint8_t		errorCode;
	uint16_t	sourcePort;
	uint16_t	destPort;
	uint16_t	state;
	uint16_t	flushType;
	uint32_t	transactionId;
	uint32_t 	sIpv4;
	uint32_t 	dIpv4;
	uint32_t	causeCode;
	uint32_t	poolIndex;
	uint64_t 	queryStartEpochSec;
	uint64_t	queryEndEpochSec;
	uint64_t 	queryStartEpochNanoSec;
	uint64_t	queryEndEpochNanoSec;
	uint64_t	dnsSessionV4Key;
	char		sIpv6[IPV6_ADDR_LEN];
	char		dIpv6[IPV6_ADDR_LEN];
	char 		URL[URL_LEN];
	char 		errorDesc[DESC_LEN];
	char		resolvedIp[IPV4_ADDR_LEN];
	string		dnsSessionV6Key;

	_dnsSession()
	{ reset(); }

	void set(const _dnsSession *obj)
	{
		this->ipVer = obj->ipVer;
		this->transactionId = obj->transactionId;

		this->sourcePort = obj->sourcePort;
		this->destPort = obj->destPort;

		this->queryStartEpochSec = obj->queryStartEpochSec;
		this->queryEndEpochSec = obj->queryEndEpochSec;
		this->queryStartEpochNanoSec = obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec = obj->queryEndEpochNanoSec;

		this->sIpv4 = obj->sIpv4;
		this->dIpv4 = obj->dIpv4;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);

		strcpy(this->URL, obj->URL);

		this->causeCode = obj->causeCode;
		this->errorCode = obj->errorCode;
		strcpy(this->errorDesc, obj->errorDesc);
		strcpy(this->resolvedIp, obj->resolvedIp);
		this->state	= obj->state;
		this->dnsSessionV4Key = obj->dnsSessionV4Key;
		this->dnsSessionV6Key = obj->dnsSessionV6Key;
		this->flushType = obj->flushType;
		this->poolIndex = obj->poolIndex;
	}

	void copy(const _dnsSession* obj)
	{
		this->ipVer = obj->ipVer;
		this->transactionId = obj->transactionId;

		this->sourcePort = obj->sourcePort;
		this->destPort = obj->destPort;

		this->queryStartEpochSec = obj->queryStartEpochSec;
		this->queryEndEpochSec = obj->queryEndEpochSec;
		this->queryStartEpochNanoSec = obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec = obj->queryEndEpochNanoSec;

		this->sIpv4 = obj->sIpv4;
		this->dIpv4 = obj->dIpv4;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);

		strcpy(this->URL, obj->URL);

		this->causeCode = obj->causeCode;
		this->errorCode = obj->errorCode;
		strcpy(this->errorDesc, obj->errorDesc);
		strcpy(this->resolvedIp, obj->resolvedIp);
		this->state = obj->state;
		this->dnsSessionV4Key = obj->dnsSessionV4Key;
		this->dnsSessionV6Key = obj->dnsSessionV6Key;
		this->flushType = obj->flushType;
		this->poolIndex = obj->poolIndex;
	}
	void reset()
	{
		ipVer = 0;
		transactionId = 0;

	    sourcePort = 0;
		destPort = 0;

		queryStartEpochSec = 0;
		queryEndEpochSec = 0;
		queryStartEpochNanoSec = 0;
		queryEndEpochNanoSec = 0;

		sIpv4 = 0;
		dIpv4 = 0;
		sIpv6[0] = 0;
		dIpv6[0] = 0;
		URL[0] = 0;

		causeCode = 0;
		errorCode = 0;
		errorDesc[0] = 0;
		resolvedIp[0] = 0;
		state = -1;
		dnsSessionV4Key = 0;
		dnsSessionV6Key.clear();
		flushType = 0;
		poolIndex = 0;
	}
}dnsSession;

typedef struct _tcpSession
{
	uint8_t		ipVer;
    uint8_t		isUpDir;
	uint8_t		causeCode;
	uint8_t		protocolType;

    uint16_t 	sPort;
    uint16_t 	dPort;
    uint16_t 	pLoadPkt;
    uint16_t 	upPLoadPkt;
    uint16_t 	dnPLoadPkt;
    uint16_t 	frCount;
    uint16_t 	upFrCount;
    uint16_t 	dnFrCount;
    uint16_t 	sliceCounter;
    uint16_t	flushOrgId;

    uint32_t	sIpv4;
    uint32_t	dIpv4;
    uint32_t	pLoadSize;
    uint32_t	upPLoadSize;
    uint32_t	dnPLoadSize;
    uint32_t	frSize;
    uint32_t	upFrSize;
    uint32_t	dnFrSize;
    uint32_t	mapIndex;
    uint32_t	poolIndex;

    uint64_t 	pckArivalTimeEpochSec;
    uint64_t 	pckLastTimeEpochSec;
    uint64_t 	pckLastTimeEpochNanoSec;
    uint64_t	startTimeEpochSec;
    uint64_t 	startTimeEpochNanoSec;
    uint64_t	endTimeEpochNanoSec;
	uint64_t	ipV4sessionKey;
	uint64_t 	flushTime;
	uint64_t 	lastActivityTimeEpohSec;

	~_tcpSession(){}

	_tcpSession()
	{ reset(); }

	void reset()
	{
	    this->ipVer 		= 0;
	    this->isUpDir		= 0;
	    this->causeCode 	= 0;
	    this->protocolType 	= 0;

	    this->sPort 		= 0;
	    this->dPort 		= 0;
	    this->pLoadPkt 		= 0;
	    this->upPLoadPkt 	= 0;
	    this->dnPLoadPkt 	= 0;
	    this->frCount 		= 0;
	    this->upFrCount 	= 0;
	    this->dnFrCount 	= 0;
	    this->sliceCounter 	= 0;
	    this->flushOrgId 	= 0;

	    this->sIpv4 		= 0;
	    this->dIpv4 		= 0;
	    this->pLoadSize 	= 0;
	    this->upPLoadSize	= 0;
	    this->dnPLoadSize 	= 0;
	    this->frSize 		= 0;
	    this->upFrSize 		= 0;
	    this->dnFrSize 		= 0;
	    this->mapIndex		= 0;
	    this->poolIndex		= 0;

	    this->pckArivalTimeEpochSec 	= 0;
	    this->pckLastTimeEpochSec 		= 0;
	    this->pckLastTimeEpochNanoSec 	= 0;
	    this->startTimeEpochSec 		= 0;
	    this->startTimeEpochNanoSec 	= 0;
	    this->endTimeEpochNanoSec 		= 0;
	    this->ipV4sessionKey 			= 0;
	    this->flushTime 				= 0;
	    this->lastActivityTimeEpohSec 	= 0;
	}

	void reuse()
	{
		this->frCount 			= 0;
		this->upFrCount 		= 0;
		this->dnFrCount 		= 0;

		this->frSize 			= 0;
		this->upFrSize 			= 0;
		this->dnFrSize 			= 0;

		this->pLoadPkt 			= 0;
		this->upPLoadPkt		= 0;
		this->dnPLoadPkt		= 0;

		this->pLoadSize 		= 0;
		this->upPLoadSize 		= 0;
		this->dnPLoadSize 		= 0;

		this->pckArivalTimeEpochSec 	= 0;
		this->startTimeEpochSec 		= pckLastTimeEpochSec;
		this->startTimeEpochNanoSec 	= pckLastTimeEpochNanoSec;

		this->endTimeEpochNanoSec 		= pckLastTimeEpochNanoSec;

		this->pckLastTimeEpochSec 		= 0;
		this->pckLastTimeEpochNanoSec 	= 0;
	}

	_tcpSession(const _tcpSession& obj)
	{
	    this->ipVer 		= obj.ipVer;
	    this->isUpDir		= obj.isUpDir;
	    this->causeCode 	= obj.causeCode;
	    this->protocolType 	= obj.protocolType;

	    this->sPort 		= obj.sPort;
	    this->dPort 		= obj.dPort;
	    this->pLoadPkt 		= obj.pLoadPkt;
	    this->upPLoadPkt 	= obj.upPLoadPkt;
	    this->dnPLoadPkt 	= obj.dnPLoadPkt;
	    this->frCount 		= obj.frCount;
	    this->upFrCount 	= obj.upFrCount;
	    this->dnFrCount 	= obj.dnFrCount;
	    this->sliceCounter 	= obj.sliceCounter;
	    this->flushOrgId 	= obj.flushOrgId;

	    this->sIpv4 		= obj.sIpv4;
	    this->dIpv4 		= obj.dIpv4;
	    this->pLoadSize 	= obj.pLoadSize;
	    this->upPLoadSize	= obj.upPLoadSize;
	    this->dnPLoadSize 	= obj.dnPLoadSize;
	    this->frSize 		= obj.frSize;
	    this->upFrSize 		= obj.upFrSize;
	    this->dnFrSize 		= obj.dnFrSize;
	    this->mapIndex		= obj.mapIndex;
	    this->poolIndex		= obj.poolIndex;

	    this->pckArivalTimeEpochSec 	= obj.pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec 		= obj.pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec 	= obj.pckLastTimeEpochNanoSec;
	    this->startTimeEpochSec 		= obj.startTimeEpochSec;
	    this->startTimeEpochNanoSec 	= obj.startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec 		= obj.endTimeEpochNanoSec;
	    this->ipV4sessionKey 			= obj.ipV4sessionKey;
	    this->flushTime 				= obj.flushTime;
	    this->lastActivityTimeEpohSec 	= obj.lastActivityTimeEpohSec;
	}

	void copy(const _tcpSession* obj)
	{
	    this->ipVer 		= obj->ipVer;
	    this->isUpDir		= obj->isUpDir;
	    this->causeCode 	= obj->causeCode;
	    this->protocolType 	= obj->protocolType;

	    this->sPort 		= obj->sPort;
	    this->dPort 		= obj->dPort;
	    this->pLoadPkt 		= obj->pLoadPkt;
	    this->upPLoadPkt 	= obj->upPLoadPkt;
	    this->dnPLoadPkt 	= obj->dnPLoadPkt;
	    this->frCount 		= obj->frCount;
	    this->upFrCount 	= obj->upFrCount;
	    this->dnFrCount 	= obj->dnFrCount;
	    this->sliceCounter 	= obj->sliceCounter;
	    this->flushOrgId 	= obj->flushOrgId;

	    this->sIpv4 		= obj->sIpv4;
	    this->dIpv4 		= obj->dIpv4;
	    this->pLoadSize 	= obj->pLoadSize;
	    this->upPLoadSize	= obj->upPLoadSize;
	    this->dnPLoadSize 	= obj->dnPLoadSize;
	    this->frSize 		= obj->frSize;
	    this->upFrSize 		= obj->upFrSize;
	    this->dnFrSize 		= obj->dnFrSize;
	    this->mapIndex		= obj->mapIndex;
	    this->poolIndex		= obj->poolIndex;

	    this->pckArivalTimeEpochSec 	= obj->pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec 		= obj->pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec 	= obj->pckLastTimeEpochNanoSec;
	    this->startTimeEpochSec 		= obj->startTimeEpochSec;
	    this->startTimeEpochNanoSec 	= obj->startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec 		= obj->endTimeEpochNanoSec;
	    this->ipV4sessionKey 			= obj->ipV4sessionKey;
	    this->flushTime 				= obj->flushTime;
	    this->lastActivityTimeEpohSec 	= obj->lastActivityTimeEpohSec;
	}
}tcpSession;

typedef struct _udpSession
{
	bool		activeState;
    uint8_t		ipVer;
    uint8_t 	sliceCounter;
    uint8_t		isUpDir;
	uint8_t		causeCode;
	uint8_t		protocolType;

	uint16_t 	state;
    uint16_t 	sPort;
    uint16_t 	dPort;
    uint16_t 	pLoadPkt;
    uint16_t 	upPLoadPkt;
    uint16_t 	dnPLoadPkt;
    uint16_t 	totalFrameCount;
    uint16_t 	frCount;
    uint16_t 	upFrCount;
    uint16_t 	dnFrCount;
	uint16_t	smInstanceId;
	uint16_t	flushOrgId;

	uint32_t	sIpv4;
    uint32_t	dIpv4;
    uint32_t	pLoadSize;
    uint32_t	upPLoadSize;
    uint32_t	dnPLoadSize;
    uint32_t	frSize;
    uint32_t	upFrSize;
    uint32_t	dnFrSize;
	uint32_t	mapIndex;
	uint32_t	poolIndex;

	uint64_t 	pckArivalTimeEpochSec;
    uint64_t 	pckLastTimeEpochSec;
    uint64_t 	pckLastTimeEpochNanoSec;
    uint64_t	startTimeEpochSec;
    uint64_t 	startTimeEpochNanoSec;
    uint64_t	endTimeEpochNanoSec;
	uint64_t	ipV4sessionKey;
	uint64_t 	flushTime;
	uint64_t 	lastActivityTimeEpohSec;

	~_udpSession(){}

	_udpSession()
	{ reset(); }

	void reset()
	{
		this->activeState 	= false;
		this->ipVer 		= 0;
		this->sliceCounter 	= 0;
		this->isUpDir		= 0;
		this->causeCode 	= 0;
		this->protocolType 	= 0;

		this->state 			= 0;
		this->sPort 			= 0;
		this->dPort 			= 0;
		this->pLoadPkt 			= 0;
		this->upPLoadPkt 		= 0;
		this->dnPLoadPkt 		= 0;
		this->totalFrameCount 	= 0;
		this->frCount 			= 0;
		this->upFrCount 		= 0;
		this->dnFrCount 		= 0;
		this->smInstanceId 		= 0;
		this->flushOrgId 		= 0;

		this->sIpv4 		= 0;
		this->dIpv4 		= 0;
		this->pLoadSize 	= 0;
		this->upPLoadSize 	= 0;
		this->dnPLoadSize 	= 0;
		this->frSize 		= 0;
	    this->upFrSize 		= 0;
	    this->dnFrSize 		= 0;
	    this->mapIndex		= 0;
	    this->poolIndex		= 0;

	    this->pckArivalTimeEpochSec 	= 0;
	    this->pckLastTimeEpochSec 		= 0;
	    this->pckLastTimeEpochNanoSec 	= 0;
	    this->startTimeEpochSec 		= 0;
	    this->startTimeEpochNanoSec 	= 0;
	    this->endTimeEpochNanoSec 		= 0;
	    this->ipV4sessionKey 			= 0;
	    this->flushTime 				= 0;
	    this->lastActivityTimeEpohSec 	= 0;
	}

	void reuse()
	{
		this->totalFrameCount 	= 0;
		this->frCount 			= 0;
		this->upFrCount 		= 0;
		this->dnFrCount 		= 0;

		this->frSize 			= 0;
		this->upFrSize 			= 0;
		this->dnFrSize 			= 0;

		this->pLoadPkt 			= 0;
		this->upPLoadPkt		= 0;
		this->dnPLoadPkt		= 0;

		this->pLoadSize 		= 0;
		this->upPLoadSize 		= 0;
		this->dnPLoadSize 		= 0;

		this->pckArivalTimeEpochSec = 0;
		this->startTimeEpochSec 	= pckLastTimeEpochSec;
		this->startTimeEpochNanoSec = pckLastTimeEpochNanoSec;
		this->endTimeEpochNanoSec 	= pckLastTimeEpochNanoSec;
		this->pckLastTimeEpochSec 	= 0;
		this->pckLastTimeEpochNanoSec = 0;
	}

	_udpSession(const _udpSession& obj)
	{
		this->activeState 	= obj.activeState;
		this->ipVer 		= obj.ipVer;
		this->sliceCounter 	= obj.sliceCounter;
		this->isUpDir		= obj.isUpDir;
		this->causeCode 	= obj.causeCode;
		this->protocolType 	= obj.protocolType;

		this->state 			= obj.state;
		this->sPort 			= obj.sPort;
		this->dPort 			= obj.dPort;
		this->pLoadPkt 			= obj.pLoadPkt;
		this->upPLoadPkt 		= obj.upPLoadPkt;
		this->dnPLoadPkt 		= obj.dnPLoadPkt;
		this->totalFrameCount 	= obj.totalFrameCount;
		this->frCount 			= obj.frCount;
		this->upFrCount 		= obj.upFrCount;
		this->dnFrCount 		= obj.dnFrCount;
		this->smInstanceId 		= obj.smInstanceId;
		this->flushOrgId 		= obj.flushOrgId;

		this->sIpv4 		= obj.sIpv4;
		this->dIpv4 		= obj.dIpv4;
		this->pLoadSize 	= obj.pLoadSize;
		this->upPLoadSize 	= obj.upPLoadSize;
		this->dnPLoadSize 	= obj.dnPLoadSize;
		this->frSize 		= obj.frSize;
	    this->upFrSize 		= obj.upFrSize;
	    this->dnFrSize 		= obj.dnFrSize;
	    this->mapIndex		= obj.mapIndex;
	    this->poolIndex		= obj.poolIndex;

	    this->pckArivalTimeEpochSec 	= obj.pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec 		= obj.pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec 	= obj.pckLastTimeEpochNanoSec;
	    this->startTimeEpochSec 		= obj.startTimeEpochSec;
	    this->startTimeEpochNanoSec 	= obj.startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec 		= obj.endTimeEpochNanoSec;
	    this->ipV4sessionKey 			= obj.ipV4sessionKey;
	    this->flushTime 				= obj.flushTime;
	    this->lastActivityTimeEpohSec 	= obj.lastActivityTimeEpohSec;
	}

	void copy(const _udpSession* obj)
	{
		this->activeState 	= obj->activeState;
		this->ipVer 		= obj->ipVer;
		this->sliceCounter 	= obj->sliceCounter;
		this->isUpDir		= obj->isUpDir;
		this->causeCode 	= obj->causeCode;
		this->protocolType 	= obj->protocolType;

		this->state 			= obj->state;
		this->sPort 			= obj->sPort;
		this->dPort 			= obj->dPort;
		this->pLoadPkt 			= obj->pLoadPkt;
		this->upPLoadPkt 		= obj->upPLoadPkt;
		this->dnPLoadPkt 		= obj->dnPLoadPkt;
		this->totalFrameCount 	= obj->totalFrameCount;
		this->frCount 			= obj->frCount;
		this->upFrCount 		= obj->upFrCount;
		this->dnFrCount 		= obj->dnFrCount;
		this->smInstanceId 		= obj->smInstanceId;
		this->flushOrgId 		= obj->flushOrgId;

		this->sIpv4 		= obj->sIpv4;
		this->dIpv4 		= obj->dIpv4;
		this->pLoadSize 	= obj->pLoadSize;
		this->upPLoadSize 	= obj->upPLoadSize;
		this->dnPLoadSize 	= obj->dnPLoadSize;
		this->frSize 		= obj->frSize;
	    this->upFrSize 		= obj->upFrSize;
	    this->dnFrSize 		= obj->dnFrSize;
	    this->mapIndex		= obj->mapIndex;
	    this->poolIndex		= obj->poolIndex;

	    this->pckArivalTimeEpochSec 	= obj->pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec 		= obj->pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec 	= obj->pckLastTimeEpochNanoSec;
	    this->startTimeEpochSec 		= obj->startTimeEpochSec;
	    this->startTimeEpochNanoSec 	= obj->startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec 		= obj->endTimeEpochNanoSec;
	    this->ipV4sessionKey 			= obj->ipV4sessionKey;
	    this->flushTime 				= obj->flushTime;
	    this->lastActivityTimeEpohSec 	= obj->lastActivityTimeEpohSec;
	}
}udpSession;

namespace DNSGlobal
{
	extern std::map<uint32_t, std::string> dnsLookUpMap[10];
	extern std::map<std::string, std::string> dnsV6LookUpMap;
}

namespace flusherStore
{
	extern std::unordered_map<uint32_t, tcpSession> tcp[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t tcpCnt[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, udpSession> udp[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t udpCnt[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, dnsSession> dns[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t dnsCnt[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, tcpSession> utcp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t utcpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, udpSession> uudp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t uudpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, dnsSession> udns[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t udnsCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
}

typedef enum{
	SYSTEM_CLEANUP_TCP_CONN_DATA		= 10,
	SYSTEM_CLEANUP_TCP_CONN_NODATA		= 11,
	SYSTEM_CLEANUP_TCP_NOCONN_DATA		= 12,
	SYSTEM_CLEANUP_TCP_NOCONN_NODATA	= 13,
	SYSTEM_CLEANUP_UDP_DATA				= 14,
	SYSTEM_CLEANUP_LONG_SESSION			= 16,
	SYSTEM_CLEANUP_TCP_DATA				= 17,
	SYSTEM_CLEANUP_END_OF_DAY_IP_DATA	= 18,

	SESSION_TERM_TCP_FIN_RECEIVED		= 20,
	SESSION_TERM_TCP_CONN_NODATA		= 21,
	SESSION_TERM_TCP_NOCONN_DATA		= 22,
	SESSION_TERM_TCP_NOCONN_NODATA		= 23,
	SESSION_TERM_TCP_OVERWRITE			= 24,

	SYSTEM_PKTLIMIT_TCP_CONN_DATA		= 30,
	SYSTEM_PKTLIMIT_TCP_NOCONN_DATA		= 31,
	SYSTEM_PKTLIMIT_UDP_DATA			= 32,

	SYSTEM_TIMEOUT_TCP_CONN_DATA		= 33,
	SYSTEM_TIMEOUT_TCP_NOCONN_DATA		= 34,
	SYSTEM_TIMEOUT_UDP_DATA				= 35,

	DUPLICATE_SYN						= 40,
	FIN_NO_SESSION						= 50,

	SYSTEM_DNS_FLUSH_REQ_RSP			= 60,
	SYSTEM_DNS_FLUSH_RSP_REQ			= 61,
	SYSTEM_CLEANUP_DNS_REQ_RSP			= 62,
	SYSTEM_CLEANUP_DNS_RSP				= 63,
	SYSTEM_CLEANUP_DNS_QUERY			= 99

}causeCode;

typedef enum{
	UD_SYN_TSVAL = 1,
	UD_SYSACK_TSVAL,
	UD_SYN_LATENCY,
	UD_TCP_DATA,
	UD_TCP_DISCONN,
	UD_UDP_DATA,
	CR_TCP_SESSION,
	CR_UDP_SESSION,
	UD_HTTP_DATA_REQ,
	UD_HTTP_DATA_RSP,
	UP_TCP_DATA_SLICE,
	TCP_UNKNOWN_PACKET_TYPE
}tcp_udp_commands;

typedef enum{
	SYN_RCV = 1,
	SYN_ACK_RCV,
	ACK_RCV,
	CONNECTED,
	DATA_RCV,
	FIN_RCV,
}IPState;

#endif /* PLUGINS_TCP_INC_SMGLOBAL_H_ */
