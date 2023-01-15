       /*
 * UnFlusher.h
 *
 *  Created on: 16-Aug-2021
 *      Author: singh
 */

#ifndef PLUGINS_UNKNOWN_INC_UNMFLUSHER_H_
#define PLUGINS_UNKNOWN_INC_UNMFLUSHER_H_

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "Log.h"
#include "ProbeUtility.h"
#include "BaseConfig.h"
#include "flusherUtility.h"
#include "dnsData.h"

class unmFlusher: dnsData {

	private:
		flusherUtility *pFlUtility;

		bool		repoInitStatus;
		uint16_t 	lastIndex;
		uint16_t 	curIndex;
		uint32_t 	totalCnt;
		uint16_t 	instanceId;

		char 		tcpXdr[XDR_MAX_LEN], udpXdr[XDR_MAX_LEN], dnsXdr[XDR_MAX_LEN];
		char 		sIpAddress[IPV4_ADDR_LEN];
		char 		dIpAddress[IPV4_ADDR_LEN];

		fstream	 	tcpXdrHandler, udpXdrHandler, dnsXdrHandler;

		void 	processTcpData(uint16_t idx);
		void 	processUdpData(uint16_t idx);
		void 	processDnsData(uint16_t idx);

		void 	flushTcpData(uint32_t &flCnt, std::unordered_map<uint32_t, tcpSession> &pkt);
		void 	flushUdpData(uint32_t &flCnt, std::unordered_map<uint32_t, udpSession> &pkt);
		void 	flushDnsData(uint32_t &flCnt, std::unordered_map<uint32_t, dnsSession> &pkt);

		bool 	createTcpXdrData(tcpSession *pTcpSession);
		bool 	createUdpXdrData(udpSession *pUdpSession);
		bool 	createDnsXdrData(dnsSession *pDnsSession);

		void	buildTcpXdr(tcpSession *pTcpSession);
		void	buildUdpXdr(udpSession *pUdpSession);

		void 	openXdrFile(uint16_t protocol, uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);
		void 	closeXdrFile(uint16_t protocol);


	public:
		unmFlusher(uint16_t id);
		~unmFlusher();

		bool 	isInitialized();
		void 	run();
};

#endif /* PLUGINS_UNKNOWN_INC_UNMFLUSHER_H_ */
