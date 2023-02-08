/*
 * SpectaProbe.h
 *
 *  Created on: 29-Jan-2016
 *      Author: Debashis
 */

#ifndef SRC_SPECTAPROBE_H_
#define SRC_SPECTAPROBE_H_

#include <signal.h>
#include <string.h>
#include <string>
#include <time.h>
#include <sys/time.h>

#include "tcpSM.h"
#include "tcpFlusher.h"

#include "udpSM.h"
#include "udpFlusher.h"

#include "dnsSM.h"
#include "dnsFlusher.h"

#include "unmSM.h"
#include "unmFlusher.h"

#include "Log.h"

#include "EthernetSource.h"
#include "SpectaTypedef.h"
#include "EthernetParser.h"
#include "BaseConfig.h"
#include "ProbeStats.h"
#include "ProbeStatsLog.h"
#include "Initialize.h"
#include "ProbeUtility.h"

#include "AdminPortReader.h"
#include "glbTimer.h"
#include "PacketRouter.h"

class SpectaProbe : public BaseConfig
{
	private:

		uint16_t currentMin, prevMin;
		timeval curTime;
		struct tm *now_tm;
		Initialize		*pInit;
		ProbeUtility 	*pUtility;

		void 	pinThread(pthread_t th, uint16_t i);

		glbTimer*			pGlbTimer;
		pthread_t			glbTimerThrId;

		tcpSM*				pTcpSM[TCP_MAX_SESSION_MANAGER_SUPPORT];
		pthread_t 			tcpSMThr[TCP_MAX_SESSION_MANAGER_SUPPORT];

		tcpFlusher*			pTcpFlusher[TCP_MAX_FLUSHER_SUPPORT];
		pthread_t 			tcpFlThr[TCP_MAX_FLUSHER_SUPPORT];

		udpSM*				pUdpSM[UDP_MAX_SESSION_MANAGER_SUPPORT];
		pthread_t 			udpSMThr[UDP_MAX_SESSION_MANAGER_SUPPORT];

		udpFlusher*			pUdpFlusher[UDP_MAX_FLUSHER_SUPPORT];
		pthread_t 			udpFlThr[UDP_MAX_FLUSHER_SUPPORT];

		dnsSM*				pDnsSM[DNS_MAX_SESSION_MANAGER_SUPPORT];
		pthread_t 			dnsSMThr[DNS_MAX_SESSION_MANAGER_SUPPORT];

		dnsFlusher*			pDnsFlusher[DNS_MAX_FLUSHER_SUPPORT];
		pthread_t 			dnsFlThr[DNS_MAX_FLUSHER_SUPPORT];

		unmSM*				pUnmSM[UNM_MAX_SESSION_MANAGER_SUPPORT];
		pthread_t 			unmSMThr[UNM_MAX_SESSION_MANAGER_SUPPORT];

		unmFlusher*			pUnmFlusher[UNM_MAX_FLUSHER_SUPPORT];
		pthread_t 			unmFlThr[UNM_MAX_FLUSHER_SUPPORT];



		PacketRouter*		pRouter[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
		pthread_t			thPktRouter[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

		EthernetSource*		ethReader[MAX_INTERFACE_SUPPORT];
		pthread_t 			pktLisThread[MAX_INTERFACE_SUPPORT];

		AdminPortReader*	adminPort;
		pthread_t			adminPortThread;

		ProbeStatsLog*		psLog;
		pthread_t 			psLogThread;

		ProbeStats*			ps;
		pthread_t 			psThread;

		IPGlobal*			pGlobal;

		void 	startInterface();
		void 	readIPRange();

		void 	initializePacketRepo();
		void 	initialize_sm_maps();
		void 	initialize_sm_flusher();

		void	commonInit();

		fstream			BwXdrHandler;

		char 	bwXdr[XDR_MAX_LEN];
		char	cachedXdr[XDR_MAX_LEN];
		char	unCachedXdr[XDR_MAX_LEN];
		void	buildBwCSV(uint64_t timems);

		void	openBwCsvXdrFile(uint16_t &currentMin, uint16_t &currentHour, uint16_t &currentDay, uint16_t &currentMonth, uint16_t &currentYear);
		void	writeBwXdr(char *buffer);
		void	closeBwCsvXdrFile();




		void 	process();
		void 	initializeLog();
		void 	initializeConfig();
		void 	readConfiguration();
		bool 	isRepositoryInitialized();

		void	createTimer(uint16_t no);
		void 	packetProcessing(bool flag);

		void 	createTcpSessionManager(uint16_t no);
		void	createTcpFlusher(uint16_t no);

		void 	createUdpSessionManager(uint16_t no);
		void	createUdpFlusher(uint16_t no);

		void 	createDnsSessionManager(uint16_t no);
		void	createDnsFlusher(uint16_t no);

		void 	createUnmSessionManager(uint16_t no);
		void	createUnmFlusher(uint16_t no);

		void	createRoutersPerInterface();

		void	initializeNICs();
		void	createAdmin();
		void	createProbeLog();
		void	createProbeStats();

	public:
		SpectaProbe(char *fileName);
		~SpectaProbe();

		GConfig 	*pGConfig;
		void 		start();
};

#endif /* SRC_SPECTAPROBE_H_ */
