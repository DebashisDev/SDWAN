/*
 * PacketRouter.h
 *
 *  Created on: Nov 22, 2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_PACKETROUTER_H_
#define CORE_SRC_PACKETROUTER_H_

#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "SpectaTypedef.h"
#include "BWData.h"
#include "EthernetParser.h"

#include "BaseConfig.h"
#include "IPGlobal.h"
#include "Log.h"

struct pcapPkthdr
{
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

class PacketRouter : public BaseConfig
{
	public:
		PacketRouter(uint16_t intfid, uint16_t rid);
		~PacketRouter();

		bool isRouterInitialized();
		void run();

	private:
		bool initStatus;
		uint16_t intfId, routerId;
		uint16_t curMin, prevMin, curHour, prevHour;
		uint16_t maxPktLen;
		int16_t	 smId;

		timeval curTime;

		MPacket*			msgObj;
		BWData*				bwData;
		EthernetParser*		ethParser;

		bool	IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask);
		void 	processQueue(uint16_t t_index);
		void 	processQueueDecode(bool &pktRepository_busy, uint32_t &pktRepository_cnt, std::unordered_map<uint32_t, RawPkt*> &pktRepository);

		void 	decodePacket(RawPkt *rawPkt);

		void	findSmForTcpPacket(MPacket* tcpPkt);
		void	pushTcpPacketToSm(int16_t smid, MPacket *msgObj);

		void	findSmForUdpPacket(MPacket* tcpPkt);
		void	pushUdpPacketToSm(int16_t smid, MPacket *msgObj);

		void	findSmForDnsPacket(MPacket* tcpPkt);
		void	pushDnsPacketToSm(int16_t smid, MPacket *msgObj);

		void	findSmForUnPacket(MPacket* tcpPkt);
		void	pushUnPacketToSm(int16_t smid, MPacket *msgObj);

		void 	copyMsgObj(uint16_t idx, bool &busy, uint32_t &counter, std::unordered_map<uint32_t, MPacket> &smStore, MPacket *msgObj);
};

#endif /* CORE_SRC_PACKETROUTER_H_ */
