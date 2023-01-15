/*
 * UnSessionManager.h
 *
 *  Created on: 15-Aug-2021
 *      Author: singh
 */

#ifndef PLUGINS_UNKNOWN_INC_UNMSM_H_
#define PLUGINS_UNKNOWN_INC_UNMSM_H_

#include <time.h>
#include <sys/time.h>
#include <sstream>
#include <locale.h>

#include "smGlobal.h"
#include "IPGlobal.h"
#include "Log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "BaseConfig.h"
#include "unmTcpInterface.h"
#include "unmUdpInterface.h"

using namespace std;

class unmSM: BaseConfig
{
	private:
		bool 			unSMReadyState;
		uint16_t		instanceId;
		uint16_t 		lastIndex;
		uint16_t 		curIndex;
		uint16_t 		curIndexClnUp, lastIndexClnUp;

		unmTcpInterface	*unTcpSM;
		unmUdpInterface	*unUdpSM;

		void 			ProcessQueue(uint16_t t_index);
		void 			processQueue_sm(bool &smBusy, uint32_t &smCnt, std::unordered_map<uint32_t, MPacket> &pkt);
		void 			processPacket(MPacket *msgObj);

	public:
		unmSM(uint16_t id);
		~unmSM();

		void			run();
		bool  			isInitialized();
};

#endif /* PLUGINS_UNKNOWN_INC_UNMSM_H_ */
