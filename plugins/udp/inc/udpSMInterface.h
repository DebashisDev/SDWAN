/*
 * udpSMInterface.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_UDP_SRC_UDPSMINTERFACE_H_
#define PLUGINS_UDP_SRC_UDPSMINTERFACE_H_

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

class udpSMInterface : BaseConfig
{
	public:
		udpSMInterface(uint16_t id);
		~udpSMInterface();

		void 		packetEntry(MPacket *msgObj);
		void		getMapIndex(MPacket *msgObj, uint32_t &idx);
		void 		sessionTimeOutClean(bool endOfDay);


	private:
			bool 			vpsFlag;
			uint16_t 		instanceId;
			uint64_t 		ipV4Key;
			std::string		ipV6Key;

			typedef struct _cleanObj
			{
				uint64_t 	ipv4key;
				string 		ipv6key;
				uint32_t 	mapIndex;
				uint32_t	poolIndex;
			}cleanObj;

			uint32_t 	freeBitPos;
			uint32_t 	freeBitPosMax;

			std::bitset<UDP_SESSION_POOL_ARRAY_ELEMENTS> bitFlagsSession[UDP_SESSION_POOL_ARRAY_SIZE];
			std::map<uint32_t, udpSession*> sessionPoolMap[UDP_SESSION_POOL_ARRAY_SIZE];

			uint32_t 	getFreeIndex();
			void 		releaseIndex(uint32_t idx);
			void 		initSessionPool();
			udpSession* getSessionFromPool(uint32_t idx);

			std::map<uint32_t, cleanObj> cleanUpMap;
			uint32_t cleanUpMapCnt;

			std::map<uint64_t, uint32_t> v4SessionMap[UDP_SESSION_POOL_ARRAY_ELEMENTS];
			std::map<std::string, uint32_t> v6SessionMap[UDP_SESSION_POOL_ARRAY_ELEMENTS];

			udpSession* getSession(MPacket *msgObj, bool *found, bool create);
			void 		eraseSession(udpSession *pUdpSession);

			void 		initializeSession(udpSession *pUdpSession, MPacket *msgObj);
			void		updateSession(udpSession *pUdpSession, MPacket *msgObj);

			void 		flushSession(uint16_t id, udpSession *pUdpSession, bool erase);
			void 		storeSession(uint16_t tIdx, udpSession *pUdpSession);

			void 		sessionTimedOutFlush(udpSession *pUdpSession, bool endOfDay);

			void		timeStampArrivalPacket(udpSession *pUdpSession, uint64_t epochSec, uint64_t epochNanoSec);
};

#endif /* PLUGINS_UDP_SRC_UDPSMINTERFACE_H_ */
