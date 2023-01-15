/*
 * dnsFlusher.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_DNS_SRC_DNSFLUSHER_H_
#define PLUGINS_DNS_SRC_DNSFLUSHER_H_

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "smGlobal.h"
#include "IPGlobal.h"
#include "Log.h"
#include "ProbeUtility.h"
#include "BaseConfig.h"
#include "flusherUtility.h"

class dnsFlusher : BaseConfig
{
	public:
		dnsFlusher(uint16_t id);
		~dnsFlusher();

		bool	isInitialized();
		void	run();

	private:
		uint16_t		instanceId;
		uint16_t 		lastIndex;
		uint16_t 		curIndex;
		bool			readyFlag;
		uint32_t 		totalCnt;
		char 			dnsXdr[XDR_MAX_LEN];

		flusherUtility *pFlUtility;
		fstream	xdrDnsHandler;

		void 	processDnsData(uint16_t idx);
		void 	flushData(uint32_t &cnt, std::unordered_map<uint32_t, dnsSession> &pkt);
		bool 	createXdrData(dnsSession *pDnsSession);

		void 	openDnsXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);
		void 	closeDnsXdrFile();
};

#endif /* PLUGINS_DNS_SRC_DNSFLUSHER_H_ */
