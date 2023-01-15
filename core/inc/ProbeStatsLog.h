/*
 * ProbeStatsLog.h
 *
 *  Created on: Jul 21, 2017
 *      Author: Debashis
 */

#ifndef CORE_SRC_PROBESTATSLOG_H_
#define CORE_SRC_PROBESTATSLOG_H_

#include <unistd.h>
#include "SpectaTypedef.h"
#include "Log.h"
#include <locale.h>
#include <time.h>
#include <sys/time.h>

#include "smGlobal.h"
#include "IPGlobal.h"
#include "BaseConfig.h"

class ProbeStatsLog : public BaseConfig
{
	public:
		ProbeStatsLog();
		~ProbeStatsLog();
		void run();

	private:
		uint16_t nicCounter, solCounter, interfaceCounter;

		timeval curTime;
		string 	INTERFACES_NAME[MAX_INTERFACE_SUPPORT] 		= {"","","","","","","",""};
		void printInterfaceStats(char *runTime);

		void printPktStoreStats_i_0();
		void printPktStoreStats_i_1();
		void printPktStoreStats_i_2();
		void printPktStoreStats_i_3();
		void printPktStoreStats_i_4();
		void printPktStoreStats_i_5();
		void printPktStoreStats_i_6();
		void printPktStoreStats_i_7();
		void eachSessionCount();
		void printDnsLookup();
		void printSessionCleanUpStats();
		void printPacketCounter();

		void printTcpCleanUpStats();
		void printUdpCleanUpStats();
		void printDnsCleanUpStats();
		void printUnmCleanUpStats();
};

#endif /* CORE_SRC_PROBESTATSLOG_H_ */
