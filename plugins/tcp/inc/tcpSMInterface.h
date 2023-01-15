/*
 * IPSMInterface.h
 *
 *  Created on: 20-Jul-2016
 *      Author: Debashis
 */

#ifndef PLUGINS_TCP_SRC_IPSMINTERFACE_H_
#define PLUGINS_TCP_SRC_IPSMINTERFACE_H_

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

class tcpSMInterface : BaseConfig
{
	private:
			uint64_t 	ipV4Key;
			std::string ipV6Key;

			bool 		vpsFlag;
			uint16_t 	instanceId;
			uint16_t 	tIdx;
			uint16_t 	flusherId;
			uint16_t 	cleanUpCnt;

			uint32_t 	freeBitPos;
			uint32_t 	freeBitPosMax;

			std::bitset<TCP_SESSION_POOL_ARRAY_ELEMENTS> bitFlagsSession[TCP_SESSION_POOL_ARRAY_SIZE];
			std::map<uint32_t, tcpSession*> sessionPoolMap[TCP_SESSION_POOL_ARRAY_SIZE];

			uint32_t 	getFreeIndex();
			void 		releaseIndex(uint32_t idx);
			void 		initSessionPool();
			tcpSession* getSessionFromPool(uint32_t idx);

			std::map<uint64_t, uint32_t> v4SessionMap[TCP_SESSION_POOL_ARRAY_ELEMENTS];
			std::map<std::string, uint32_t> v6SessionMap[TCP_SESSION_POOL_ARRAY_ELEMENTS];


			tcpSession* getSession(MPacket *msgObj, bool *found, bool create);
			void 		eraseSession(tcpSession *pIpSession);

			void 		initializeSession(tcpSession *pIpSession, MPacket *msgObj);
			void		updateTcpSession(tcpSession *pIpSession, MPacket *msgObj);

			void 		flushSession(uint16_t id, tcpSession *pIpSession, bool erase);
			void 		storeSession(uint16_t tIdx, tcpSession *pIpSession);

			void 		sessionTimedOutFlush(tcpSession *pIpSession, bool endOfDay);

			void		timeStampArrivalPacket(tcpSession *pIpSession, uint64_t epochSec, uint64_t epochNanoSec);
			void		updateTime(tcpSession *pIpSession, int id);

	public:
			tcpSMInterface(uint16_t id);
			~tcpSMInterface();

			void 		packetEntry(MPacket *msgObj);
			void		getMapIndex(MPacket *msgObj, uint32_t &idx);
			void 		sessionTimeOutClean(bool endOfDay);

//			void 		IP_UdpProcessPacket(MPacket *msgObj);
//			void 		IP_DnsProcessPacket(MPacket *msgObj);
//			void 		IPv4_DnsDumpLookUp(int day);
//			void 		IPv4_DnsLoadLookUp();
//			void 		IPv6_DnsDumpLkuInfo(int HR);
//			void 		IPv6_DnsLoadLoopUp();
//			void 		dnsSessionTimeOutClean();

};

#endif /* PLUGINS_TCP_SRC_IPSMINTERFACE_H_ */
