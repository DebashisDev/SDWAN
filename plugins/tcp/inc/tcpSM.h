/*
 * IPSessionManager.h
 *
 *  Created on: Apr 24, 2017
 *      Author: Debashis
 */

#ifndef PLUGINS_TCP_SRC_IPSESSIONMANAGER_H_
#define PLUGINS_TCP_SRC_IPSESSIONMANAGER_H_

#include <time.h>
#include <sys/time.h>
#include <sstream>
#include <locale.h>

#include "IPGlobal.h"
#include "Log.h"
#include "tcpSMInterface.h"

using namespace std;

class tcpSM : BaseConfig
{
	public:
		tcpSM(uint16_t id);
		~tcpSM();

		void	run();
		bool  	isInitialized();

	private:
		uint16_t		instanceId;
		bool 			initStats;
		uint16_t 		lastTidx, curTidx, curIndexClnUp, lastIndexClnUp;

		tcpSMInterface		*pTcpSMInterface;

		void	lockDnsMap();
		void	unLockDnsMap();
		void	lockRadiusMap();
		void	unLockRadiusMap();

		void 	processQueue(uint16_t t_index);
		void 	processPackets(bool &ip_msg_sm_busy, uint32_t &ip_msg_sm_cnt, std::unordered_map<uint32_t, MPacket> &ip_msg_sm);

		void 	callInterface(MPacket *msgObj);

		void	executeDayEndActivity();
};

#endif /* PLUGINS_TCP_SRC_IPSESSIONMANAGER_H_ */
