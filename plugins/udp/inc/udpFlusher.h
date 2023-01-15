/*
 * udpFlusher.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_UDP_SRC_UDPFLUSHER_H_
#define PLUGINS_UDP_SRC_UDPFLUSHER_H_

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "IPGlobal.h"
#include "smGlobal.h"
#include "Log.h"
#include "ProbeUtility.h"
#include "BaseConfig.h"
#include "flusherUtility.h"

class udpFlusher : BaseConfig
{
	private:
		uint16_t		instanceId;
		uint32_t 		totalCnt;
		uint16_t 		lastTidx, curTidx;
		fstream	 		xdrUdpHandler;
		flusherUtility 	*fUtil;

		bool	initStatus;
		char 	udpXdr[XDR_MAX_LEN];

		void 	processUdpData(uint16_t index);
		void 	getUdpData(uint32_t &flCnt, std::unordered_map<uint32_t, udpSession> &fStore);
		bool 	createUdpXdrData(udpSession *pUdpSession);

		void 	openUdpXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);
		void 	closeUdpXdrFile();

	public:
		udpFlusher(uint16_t id);
		~udpFlusher();
		bool 	isInitialized();
		void 	run();
};

#endif /* PLUGINS_UDP_SRC_UDPFLUSHER_H_ */
