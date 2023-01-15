/*
 * dnsSM.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_DNS_SRC_DNSSM_H_
#define PLUGINS_DNS_SRC_DNSSM_H_

#include <time.h>
#include <sys/time.h>
#include <sstream>
#include <locale.h>

#include "IPGlobal.h"
#include "Log.h"
#include "dnsSMInterface.h"
#include "udpSMInterface.h"

using namespace std;

class dnsSM : BaseConfig
{
	public:
		dnsSM(uint16_t id);
		~dnsSM();

		void	run();
		bool  	isInitialized();

	private:
		uint16_t		instanceId;
		bool 			initStats;
		uint16_t 		lastTidx, curTidx, curIndexClnUp, lastIndexClnUp;

		dnsSMInterface		*pDnsSMInterface;
		udpSMInterface		*pUdpSMInterface;

		void	lockDnsMap();
		void	unLockDnsMap();

		void 	processQueue(uint16_t t_index);
		void 	processPackets(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, MPacket> &store);

		void 	callInterface(MPacket *msgObj);

		void	executeDayEndActivity();

};

#endif /* PLUGINS_DNS_SRC_DNSSM_H_ */
