/*
 * udpSM.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_UDP_SRC_UDPSM_H_
#define PLUGINS_UDP_SRC_UDPSM_H_

#include <time.h>
#include <sys/time.h>
#include <sstream>
#include <locale.h>

#include "IPGlobal.h"
#include "Log.h"
#include "udpSMInterface.h"

using namespace std;

class udpSM : BaseConfig
{
	public:
		udpSM(uint16_t id);
		~udpSM();

		void	run();
		bool  	isInitialized();

	private:
		uint16_t		instanceId;
		bool 			initStats;
		uint16_t 		lastTidx, curTidx, curIndexClnUp, lastIndexClnUp;

		udpSMInterface		*pUdpSMInterface;

		void	lockDnsMap();
		void	unLockDnsMap();
		void 	processQueue(uint16_t t_index);
		void 	processPackets(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, MPacket> &store);

		void 	callInterface(MPacket *msgObj);

		void	executeDayEndActivity();
};

#endif /* PLUGINS_UDP_SRC_UDPSM_H_ */
