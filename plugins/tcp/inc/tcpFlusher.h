/*
 * IPFlusher.h
 *
 *  Created on: Apr 24, 2017
 *      Author: Debashis
 */

#ifndef PLUGINS_TCP_SRC_IPFLUSHER_H_
#define PLUGINS_TCP_SRC_IPFLUSHER_H_

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

class tcpFlusher : BaseConfig
{
	private:
		uint16_t		instanceId;
		uint16_t 		lastTidx, curTidx;
		uint32_t 		totalCnt;
		fstream	 		xdrTcpHandler;
		flusherUtility *fUtil;

		bool	initStatus;
		char 	tcpXdr[XDR_MAX_LEN];

		void 	processTcpData(uint16_t index);
		void 	getTcpData(uint32_t &flCnt, std::unordered_map<uint32_t, tcpSession> &fStore);
		bool 	createTcpXdrData(tcpSession *pIpSession);

		void 	openTcpXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);
		void 	closeTcpXdrFile();


	public:
			tcpFlusher(uint16_t id);
			~tcpFlusher();
			bool 	isInitialized();
			void 	run();
};
#endif /* PLUGINS_TCP_SRC_IPFLUSHER_H_ */
