/*
 * dnsSMInterface.h
 *
 *  Created on: 22 Sep 2021
 *      Author: Debashis
 */

#ifndef PLUGINS_DNS_SRC_DNSSMINTERFACE_H_
#define PLUGINS_DNS_SRC_DNSSMINTERFACE_H_

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <string>

#include "IPGlobal.h"
#include "SpectaTypedef.h"
#include "Log.h"
#include "BaseConfig.h"
#include "smGlobal.h"

#define DNS_FLUSH_REQ_RSP		30
#define DNS_FLUSH_RSP_REQ		31
#define DNS_FLUSH_CLEANUP_REQ_RSP	32
#define DNS_FLUSH_CLEANUP_REQ_NORSP	33
#define DNS_FLUSH_CLEANUP_RSP_NOREQ	34

class dnsSMInterface : BaseConfig
{
	public:
		dnsSMInterface(uint16_t id);
		~dnsSMInterface();

		void		DnsPacketEntry(MPacket *udpMsg);
		void		sessionTimeOutClean();

	private:
		uint16_t	instanceId;
		uint64_t 	ipV4Key;
		std::string ipV6Key;

		typedef struct _cleanObj
		{
			uint64_t ipv4key;
			string ipv6key;
			uint32_t poolIndex;
		}cleanObj;

		uint32_t freeBitPos;
		uint32_t freeBitPosMax;

		std::bitset<DNS_SESSION_POOL_ARRAY_ELEMENTS> bitFlagsSession[DNS_SESSION_POOL_ARRAY_SIZE];
		std::map<uint32_t, dnsSession*> sessionPoolMap[DNS_SESSION_POOL_ARRAY_SIZE];
		uint32_t 	getFreeIndex();
		void 	releaseIndex(uint32_t idx);
		void 	initializeSessionPool();

		dnsSession* getSessionFromPool(uint32_t idx);
		std::map<uint32_t, cleanObj> sessionCleanUpMap;
		uint32_t sessionCleanCnt = 0;

		std::map<uint64_t, uint32_t> dnsV4SessionMap;
		std::map<string, uint32_t> dnsV6SessionMap;

		void		requestUpdateSession(dnsSession *pDnsSession, MPacket *msgObj);
		void 		responseUpdateSession(dnsSession *pDnsSession, MPacket *msgObj);
		dnsSession* getDnsSession(MPacket *msgObj, bool *found);

		void 		getIpv6SessionKey(std::string &key, char* userAddrLong, uint32_t dnsTransactionId, uint16_t port);
		void		getIpv4SessionKey(uint64_t &key, uint32_t userAddrLong, uint16_t port, uint32_t destAddrLong, uint32_t dnsTransactionId);

		void 		flushSession(dnsSession *pDnsSession, int type);
		void		storeSession(uint16_t idx, dnsSession *pDnsSession);

		void		loadResolvedIpv4();
		void		loadResolvedIpv6();
		void		dnsIpV4LookUpCount();
};

#endif /* PLUGINS_DNS_SRC_DNSSMINTERFACE_H_ */
