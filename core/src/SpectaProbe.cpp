/*
 * SpectaProbe.cpp
 *
 *  Created on: 29-Jan-2016
 *      Author: Debashis
 */

#include <signal.h>
#include <unistd.h>
#include <locale.h>
#include <zmq.h>

#include "SpectaProbe.h"

void *startTimerThread(void *arg)
{
	glbTimer *ft = (glbTimer *)arg;
	ft->run();
	return NULL;
}

void* tcpSMThread(void* arg)
{
	tcpSM *ft = (tcpSM*)arg;
	ft->run();
	return NULL;
}

void* tcpFlusherThread(void* arg)
{
	tcpFlusher *ft = (tcpFlusher*)arg;
	ft->run();
	return NULL;
}

void* udpSMThread(void* arg)
{
	udpSM *ft = (udpSM*)arg;
	ft->run();
	return NULL;
}

void* udpFlusherThread(void* arg)
{
	udpFlusher *ft = (udpFlusher*)arg;
	ft->run();
	return NULL;
}

void* dnsSMThread(void* arg)
{
	dnsSM *ft = (dnsSM*)arg;
	ft->run();
	return NULL;
}

void* dnsFlusherThread(void* arg)
{
	dnsFlusher *ft = (dnsFlusher*)arg;
	ft->run();
	return NULL;
}

void* unmSMThread(void* arg)
{
	unmSM *ft = (unmSM*)arg;
	ft->run();
	return NULL;
}

void* unmFlusherThread(void* arg)
{
	unmFlusher *ft = (unmFlusher*)arg;
	ft->run();
	return NULL;
}

void* startPktRouterThread(void* arg)
{
	int s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	PacketRouter *ft = (PacketRouter*)arg;
	ft->run();
	return NULL;
}

void* ethListenerThread(void* arg)
{
	EthernetSource *ft = (EthernetSource*)arg;
	ft->start();
	return NULL;
}

void* probeStatsThread(void* arg)
{
	ProbeStats *ft = (ProbeStats*)arg;
	ft->run();
	return NULL;
}

void* probeStatsLogThread(void* arg)
{
	ProbeStatsLog *ft = (ProbeStatsLog*)arg;
	ft->run();
	return NULL;
}

void* adminPortListenerThread(void* arg)
{
	AdminPortReader *ft = (AdminPortReader*)arg;
	ft->run();
	return NULL;
}

SpectaProbe::SpectaProbe(char *fileName)
{
	this->_name = "SpectaProbe";
	this->setLogLevel(Log::theLog().level());

	pInit 		= new Initialize();
	pGConfig 	= new GConfig();
	pUtility 	= new ProbeUtility();

	pGConfig->initialize(fileName);

	initializeLog();
}

SpectaProbe::~SpectaProbe()
{
	delete(pInit);
	delete(pGConfig);
	delete(pUtility);
}

void SpectaProbe::initializeLog()
{
	char logFile[200];
	char probeName[10];

	logFile[0] = 0;
	sprintf(logFile, "%s%s_%d.log", Global::LOG_DIR.c_str(), "probe", Global::PROBE_ID);

	Log::theLog().open(logFile);
	Log::theLog().level(Global::LOG_LEVEL);

	strcpy(probeName, " FixedLine ");

	char *probeVer = getenv("PROBE_VER");

	printf(" ############################################################\n");
	printf("                                                             \n");
	printf("              Starting SPECTA [%s] Probe Ver : %s            \n", probeName, probeVer);
	printf("                                                             \n");
	printf(" ############################################################\n");


	TheLog_nc_v1(Log::Info, name(),"  ############################################################%s","");
	TheLog_nc_v1(Log::Info, name(),"                                                              %s","");
	TheLog_nc_v2(Log::Info, name(),"                     Starting SPECTA [%s] Probe Ver : %s        ", probeName, probeVer);
	TheLog_nc_v1(Log::Info, name(),"                                                              %s","");
	TheLog_nc_v1(Log::Info, name(),"  ############################################################%s","");
	TheLog_nc_v1(Log::Info, name(),"  Log file initialized Level - %d", Global::LOG_LEVEL);
}

void SpectaProbe::start()
{
	uint16_t infid, totalNoRouter, startRouterId;

	infid = totalNoRouter = startRouterId = 0;
	Global::NO_OF_INTERFACES = Global::NO_OF_NIC_INTERFACE;

	initializePacketRepo();
	initialize_sm_maps();
	initialize_sm_flusher();

	/* Protocol Name, Dns , TCP Ports */
	commonInit();

	/* Create timer */
	createTimer(1);

	/* Pause Traffic */
	packetProcessing(false);

	/* TCP SM Threads Creation */
	createTcpSessionManager(2);

	/* TCP Flusher Threads Creation */
	createTcpFlusher(3);

	/* UDP SM Threads Creation */
	createUdpSessionManager(2);

	/* UDP Flusher Threads Creation */
	createUdpFlusher(3);

	/* DNS SM Threads Creation */
	createDnsSessionManager(2);

	/* DNS Flusher Threads Creation */
	createDnsFlusher(3);

	if(Global::PROCESS_OUT_OF_RANGE_IP)
	{
		/* UNM SM Threads Creation */
		createUnmSessionManager(2);

		/* UNM Flusher Threads Creation */
		createUnmFlusher(3);
	}

	createRoutersPerInterface();		/* Router / Interface Threads Created */

	initializeNICs();					/* Initialize NICs */

	createAdmin();						/* Create a Thread to Listen to ADMIN Port */

	createProbeLog();					/* Create a Thread to create Log File */

	createProbeStats();					/* Create a Thread to create probe Status */

	pUtility->loadResolvedIpv4(Global::DATA_DIR);

	sleep(15); /* Start Processing the data after 30 seconds */

	printf(" ** Specta Probe Started.\n");
	TheLog_nc_v1(Log::Info, name(),"  Started successfully.%s","");

	packetProcessing(true);			/* Resume the incoming Traffic */

	int cnt = 0, today = 0, lastday = 0, dnsDumpLoop = 0;
	int minCheckCnt = 60 / 1;

	lastday = today =  Global::CURRENT_DAY;

	currentMin = prevMin = Global::CURRENT_MIN;

	while(Global::PROBE_RUNNING_STATUS)
	{
		sleep(1);
		currentMin = Global::CURRENT_MIN;

		if(currentMin != prevMin)
		{
			dnsDumpLoop ++;

			if(dnsDumpLoop >= 2)
			{
				dnsDumpLoop = 0;
				pUtility->dnsDumpIpv4Data(Global::DATA_DIR);
			}

			prevMin = currentMin;
		}
		if(lastday != today)
		{
			lastday = today;
			TheLog_nc(Log::Info, name(),"  Day Changed .... !!! Initializing Counters....");

			for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
				for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; i++)
				{
					Global::TCP_PACKETS_PER_DAY[i][r] = 0;
					Global::UDP_PACKETS_PER_DAY[i][r] = 0;
					Global::DNS_PACKETS_PER_DAY[i][r] = 0;
				}

			for(int i=0; i<Global::NO_OF_INTERFACES; i++)
					Global::DISCARDED_PACKETS[i] = 0;
		}
	}
	printf("\n *** Shutdown SpectaProbe Complete.\n");
	TheLog_nc_v1(Log::Info, name(),"  Shutdown Completed.%s","");
	exit(0);
}

/* Create timer */
void SpectaProbe::createTimer(uint16_t no)
{
	pGlbTimer = new glbTimer;

	pthread_create(&glbTimerThrId, NULL, startTimerThread, pGlbTimer);
	pinThread(glbTimerThrId, Global::TIMER_CPU_CORE);

	while(!pGlbTimer->isGlbTimerInitialized())
		sleep(1);

	printf("  *** [%02d] Timer Thread Started Successfully. Pinned to CPU Core [%02d]\n", no, Global::TIMER_CPU_CORE);
	TheLog_nc_v2(Log::Info, name(),"  *** [%02d] Timer Thread Started Successfully. Pinned to CPU Core [%02d]", no, Global::TIMER_CPU_CORE);

}

/* Pause / Start Traffic */
void SpectaProbe::packetProcessing(bool flag)
{
	switch(flag)
	{
		case true:
			for(uint16_t infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
			{
				Global::PACKET_PROCESSING[infCounter] = true;
				sleep(60);
			}
			break;

		case false:
			for(uint16_t infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
			{
				Global::PACKET_PROCESSING[infCounter] = false;
			}

			break;
	}
}

/* create TCP SM */
void SpectaProbe::createTcpSessionManager(uint16_t no)
{
	for(uint16_t i = 0; i < Global::TCP_SESSION_MANAGER_INSTANCES; i++)
	{
		Global::TCP_SESSION_MANAGER_RUNNING_STATUS[i] = true;
		pTcpSM[i] = new tcpSM(i);
		pthread_create(&tcpSMThr[i], NULL, tcpSMThread, pTcpSM[i]);
		pinThread(tcpSMThr[i], Global::TCP_SESSION_MANAGER_CPU_CORE[i]);

		printf("  *** [%02d] TCP SM Instance - %02d| Allocated Core - %2d\n", no, i, Global::TCP_SESSION_MANAGER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] TCP SM Instance - %02d| Allocated Core - %2d", no, i, Global::TCP_SESSION_MANAGER_CPU_CORE[i]);

		while(!pTcpSM[i]->isInitialized())
			sleep(1);
	}
}

/* Create TCP Flusher */
void SpectaProbe::createTcpFlusher(uint16_t no)
{
	for(uint16_t i = 0; i < Global::NO_OF_TCP_FLUSHER; i++)
	{
		Global::TCP_FLUSHER_RUNNING_STATUS[i] = true;
		pTcpFlusher[i] = new tcpFlusher(i);
		pthread_create(&tcpFlThr[i], NULL, tcpFlusherThread, pTcpFlusher[i]);
		pinThread(tcpFlThr[i], Global::TCP_FLUSHER_CPU_CORE[i]);

		printf("  *** [%02d] TCP Flusher Instance - %02d| Allocated Core - %2d\n", no, i, Global::TCP_FLUSHER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] TCP Flusher Instance - %02d| Allocated Core - %2d", no, i, Global::TCP_FLUSHER_CPU_CORE[i]);

		while(!pTcpFlusher[i]->isInitialized())
			sleep(1);
	}
}

/* Create UDP SM */
void SpectaProbe::createUdpSessionManager(uint16_t no)
{
	for(uint16_t i = 0; i < Global::UDP_SESSION_MANAGER_INSTANCES; i++)
	{
		Global::UDP_SESSION_MANAGER_RUNNING_STATUS[i] = true;
		pUdpSM[i] = new udpSM(i);
		pthread_create(&udpSMThr[i], NULL, udpSMThread, pUdpSM[i]);
		pinThread(udpSMThr[i], Global::UDP_SESSION_MANAGER_CPU_CORE[i]);

		printf("  *** [%02d] UDP SM Instance - %02d| Allocated Core - %2d\n", no, i, Global::UDP_SESSION_MANAGER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] UDP SM Instance - %02d| Allocated Core - %2d", no, i, Global::UDP_SESSION_MANAGER_CPU_CORE[i]);

		while(!pUdpSM[i]->isInitialized())
			sleep(1);
	}
}

/* Create UDP Flusher */
void SpectaProbe::createUdpFlusher(uint16_t no)
{
	for(uint16_t i = 0; i < Global::NO_OF_UDP_FLUSHER; i++)
	{
		Global::UDP_FLUSHER_RUNNING_STATUS[i] = true;
		pUdpFlusher[i] = new udpFlusher(i);
		pthread_create(&udpFlThr[i], NULL, udpFlusherThread, pUdpFlusher[i]);
		pinThread(udpFlThr[i], Global::UDP_FLUSHER_CPU_CORE[i]);

		printf("  *** [%02d] UDP Flusher Instance - %02d| Allocated Core - %2d\n", no, i, Global::UDP_FLUSHER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] UDP Flusher Instance - %02d| Allocated Core - %2d", no, i, Global::UDP_FLUSHER_CPU_CORE[i]);

		while(!pUdpFlusher[i]->isInitialized())
			sleep(1);
	}
}

/* Create DNS SM */
void SpectaProbe::createDnsSessionManager(uint16_t no)
{
	for(uint16_t i = 0; i < Global::DNS_SESSION_MANAGER_INSTANCES; i++)
	{
		Global::DNS_SESSION_MANAGER_RUNNING_STATUS[i] = true;
		pDnsSM[i] = new dnsSM(i);
		pthread_create(&dnsSMThr[i], NULL, dnsSMThread, pDnsSM[i]);
		pinThread(dnsSMThr[i], Global::DNS_SESSION_MANAGER_CPU_CORE[i]);

		printf("  *** [%02d] DNS SM Instance - %02d| Allocated Core - %2d\n", no, i, Global::DNS_SESSION_MANAGER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] DNS SM Instance - %02d| Allocated Core - %2d", no, i, Global::DNS_SESSION_MANAGER_CPU_CORE[i]);

		while(!pDnsSM[i]->isInitialized())
			sleep(1);
	}
}

/* Create DNS Flusher */
void SpectaProbe::createDnsFlusher(uint16_t no)
{
	for(uint16_t i = 0; i < Global::NO_OF_DNS_FLUSHER; i++)
	{
		Global::DNS_FLUSHER_RUNNING_STATUS[i] = true;
		pDnsFlusher[i] = new dnsFlusher(i);
		pthread_create(&dnsFlThr[i], NULL, dnsFlusherThread, pDnsFlusher[i]);
		pinThread(dnsFlThr[i], Global::DNS_FLUSHER_CPU_CORE[i]);

		printf("  *** [%02d] DNS Flusher Instance - %02d| Allocated Core - %2d\n", no, i, Global::DNS_FLUSHER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] DNS Flusher Instance - %02d| Allocated Core - %2d", no, i, Global::DNS_FLUSHER_CPU_CORE[i]);

		while(!pDnsFlusher[i]->isInitialized())
			sleep(1);
	}
}

/* Create UNM SM */
void SpectaProbe::createUnmSessionManager(uint16_t no)
{
	for(uint16_t i = 0; i < Global::UNM_SESSION_MANAGER_INSTANCES; i++)
	{
		Global::UNM_SESSION_MANAGER_RUNNING_STATUS[i] = true;
		pUnmSM[i] = new unmSM(i);
		pthread_create(&unmSMThr[i], NULL, unmSMThread, pUnmSM[i]);
		pinThread(unmSMThr[i], Global::UNMAPPED_SESSION_MANAGER_CPU_CORE[i]);

		printf("  *** [%02d] UNM SM Instance - %02d| Allocated Core - %2d\n", no, i, Global::UNMAPPED_SESSION_MANAGER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] UNM SM Instance - %02d| Allocated Core - %2d", no, i, Global::UNMAPPED_SESSION_MANAGER_CPU_CORE[i]);

		while(!pUnmSM[i]->isInitialized())
			sleep(1);
	}
}

/* Create UNM Flusher */
void SpectaProbe::createUnmFlusher(uint16_t no)
{
	for(uint16_t i = 0; i < Global::NO_OF_UNM_FLUSHER; i++)
	{
		Global::UNM_FLUSHER_RUNNING_STATUS[i] = true;
		pUnmFlusher[i] = new unmFlusher(i);
		pthread_create(&unmFlThr[i], NULL, unmFlusherThread, pUnmFlusher[i]);
		pinThread(unmFlThr[i], Global::UNM_FLUSHER_CPU_CORE[i]);

		printf("  *** [%02d] UNM Flusher Instance - %02d| Allocated Core - %2d\n", no, i, Global::UNM_FLUSHER_CPU_CORE[i]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] UNM Flusher Instance - %02d| Allocated Core - %2d", no, i, Global::UNM_FLUSHER_CPU_CORE[i]);

		while(!pUnmFlusher[i]->isInitialized())
			sleep(1);
	}
}

void SpectaProbe::createRoutersPerInterface()
{
	Global::NO_OF_ROUTERS = 0;

	for(uint16_t infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
	{
		for(uint16_t routeCounter = 0; routeCounter < Global::ROUTER_PER_INTERFACE[infCounter]; routeCounter++)
		{
			Global::NO_OF_ROUTERS += 1;
			Global::PKT_ROUTER_RUNNING_STATUS[infCounter][routeCounter] = true;
			gettimeofday(&curTime, NULL);

			pRouter[infCounter][routeCounter] = new PacketRouter(infCounter, routeCounter);
			pthread_create(&thPktRouter[infCounter][routeCounter], NULL, startPktRouterThread, pRouter[infCounter][routeCounter]);

			pinThread(thPktRouter[infCounter][routeCounter], Global::PKT_ROUTER_CPU_CORE[infCounter][routeCounter]);
			printf("  *** PacketRouter [Interface]::[Router] [%02d]::[%02d] Allocated Core [%02d]\n", infCounter, routeCounter, Global::PKT_ROUTER_CPU_CORE[infCounter][routeCounter]);

			TheLog_nc_v3(Log::Info, name(),"  *** PacketRouter Instance [%d][%d] Allocated Core [%d]", infCounter, routeCounter, Global::PKT_ROUTER_CPU_CORE[infCounter][routeCounter]);
			while(!pRouter[infCounter][routeCounter]->isRouterInitialized())
				sleep(1);
		}
	}

}

void SpectaProbe::initializeNICs()
{
	for(int infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
	{
		printf("Started NIC   Listener for Interface [%d]->[%s] with No of Routers [%02d] Pinned to CPU Core [%02d] \n",
				infCounter, Global::ETHERNET_INTERFACES[infCounter].c_str(), Global::ROUTER_PER_INTERFACE[infCounter], Global::PKT_LISTENER_CPU_CORE[infCounter]);

		Global::PNAME[infCounter] = Global::ETHERNET_INTERFACES[infCounter];

		Global::PKT_LISTENER_RUNNING_STATUS[infCounter] = true;
		ethReader[infCounter] = new EthernetSource(Global::ROUTER_PER_INTERFACE[infCounter], infCounter);
		pthread_create(&pktLisThread[infCounter], NULL, ethListenerThread, ethReader[infCounter]);
		pinThread(pktLisThread[infCounter], Global::PKT_LISTENER_CPU_CORE[infCounter]);

		while(!ethReader[infCounter]->isRepositoryInitialized())
			sleep(1);
	}
}

void SpectaProbe::createAdmin()
{
	if(Global::ADMIN_FLAG)
	{
		adminPort = new AdminPortReader();
		pthread_create(&adminPortThread, NULL, adminPortListenerThread, adminPort);
		sleep(1);
	}
}

void SpectaProbe::createProbeLog()
{
	psLog = new ProbeStatsLog();
	pthread_create(&psLogThread, NULL, probeStatsLogThread, psLog);
}

void SpectaProbe::createProbeStats()
{
	if(Global::PRINT_STATS)
	{
		ps = new ProbeStats();
		pthread_create(&psThread, NULL, probeStatsThread, ps);
	}
}

void SpectaProbe::pinThread(pthread_t th, uint16_t i)
{
   /* Set affinity mask to include CPUs 0 to 7 */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(i,&cpuset);

	int s = pthread_setaffinity_np(th, sizeof(cpu_set_t), &cpuset);
	if (s != 0)
		handle_error_en(s, "ERROR!!! pthread_setaffinity_np");

	/* Check the actual affinity mask assigned to the thread */
	s = pthread_getaffinity_np(th, sizeof(cpu_set_t), &cpuset);
	if (s != 0)
		handle_error_en(s, "ERROR!!! pthread_getaffinity_np");

	if (!CPU_ISSET(i, &cpuset)){
		printf("CPU pinning failed at core :: %d\n", i);
		TheLog_nc_v1(Log::Info, name(),"  CPU pinning failed at core :: %d",i);
	}
}

void SpectaProbe::initializePacketRepo()
{
	uint32_t maxLen = 0;

	for(uint16_t intf = 0; intf < Global::NO_OF_INTERFACES; intf++)
	{
		maxLen = Global::PPS_PER_INTERFACE[intf] / Global::ROUTER_PER_INTERFACE[intf];

		printf("PKTStore Repository for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt... ", intf, maxLen, Global::ROUTER_PER_INTERFACE[intf]);
		TheLog_nc_v3(Log::Info, name(),"  PKTStore Repository for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt...", intf, maxLen, Global::ROUTER_PER_INTERFACE[intf]);

		for(uint16_t router = 0; router < Global::ROUTER_PER_INTERFACE[intf]; router++)
		{
			for(uint16_t ti = 0; ti < 10; ti++)
			{
				PKTStore::cnt[intf][router][ti] = 0;
				PKTStore::busy[intf][router][ti] = false;

				for(uint32_t ml = 0; ml < maxLen; ml++)
					PKTStore::store[intf][router][ti][ml] = new RawPkt(Global::MAX_PKT_LEN_PER_INTERFACE[intf]);
			}
		}
		printf("Completed for Interface [%d] Initializing [%'d] per Router x 10 x %d Router\n", intf, maxLen, Global::ROUTER_PER_INTERFACE[intf]);
		TheLog_nc_v3(Log::Info, name(),"  PKTStore Repository for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt...Completed", intf, maxLen, Global::ROUTER_PER_INTERFACE[intf]);
	}
}

void SpectaProbe::initialize_sm_maps()
{
	printf("\n *** Initializing SM Queues ***");

	for(int sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
		for(int intf = 0; intf < Global::NO_OF_INTERFACES; intf++)
			for(int router = 0; router < Global::ROUTER_PER_INTERFACE[intf]; router++)
				for(int ti = 0; ti < 10; ti++)
				{
					SmStore::tcpBusy[sm][intf][router][ti] = false;
					SmStore::tcpCnt[sm][intf][router][ti] = 0;
				}
}

void SpectaProbe::initialize_sm_flusher()
{
	printf("\n *** Initializing SM Flusher Queues ***");

	for(int flusher = 0; flusher < Global::NO_OF_TCP_FLUSHER; flusher++)
		for(int sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
			for(int ti = 0; ti < 10; ti++)
				flusherStore::tcpCnt[flusher][sm][ti] = 0;

	for(int flusher = 0; flusher < Global::NO_OF_DNS_FLUSHER; flusher++)
		for(int sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
			for(int ti = 0; ti < 10; ti++)
				flusherStore::dnsCnt[flusher][sm][ti] = 0;
}

void SpectaProbe::commonInit()
{
	pGlobal = new IPGlobal();

	pGlobal->initProtocolName();
	pGlobal->dnsErrorCode();
	pGlobal->tcpPorts();
}

void SpectaProbe::buildBwCSV(uint64_t timems)
{
	bwXdr[0] = 0;

	bwData bw_i[MAX_INTERFACE_SUPPORT];

	for(uint16_t intf = 0; intf < Global::NO_OF_INTERFACES; intf++)
		for(uint16_t router = 0; router < Global::ROUTER_PER_INTERFACE[intf]; router++)
		{
			bw_i[intf].peakTotalVol += Global::BW_MBPS_i_r[intf][router].peakTotalVol;
			bw_i[intf].peakUpTotalVol += Global::BW_MBPS_i_r[intf][router].peakUpTotalVol;
			bw_i[intf].peakDnTotalVol += Global::BW_MBPS_i_r[intf][router].peakDnTotalVol;
			bw_i[intf].totalVol += Global::BW_MBPS_i_r[intf][router].totalVol;
			bw_i[intf].upTotalVol += Global::BW_MBPS_i_r[intf][router].upTotalVol;
			bw_i[intf].dnTotalVol += Global::BW_MBPS_i_r[intf][router].dnTotalVol;
			bw_i[intf].avgTotalBw += Global::BW_MBPS_i_r[intf][router].avgTotalBw;
			bw_i[intf].avgUpBw += Global::BW_MBPS_i_r[intf][router].avgUpBw;
			bw_i[intf].avgDnBw += Global::BW_MBPS_i_r[intf][router].avgDnBw;
		}


	sprintf(bwXdr, "%d,%d,"
					"%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,"
					"%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu",
			Global::PROBE_ID, IP_XDR_ID,
			timems,
			bw_i[0].peakTotalVol*8, bw_i[0].peakUpTotalVol*8, bw_i[0].peakDnTotalVol*8, bw_i[0].totalVol, bw_i[0].upTotalVol, bw_i[0].dnTotalVol, bw_i[0].avgTotalBw, bw_i[0].avgUpBw, bw_i[0].avgDnBw,
			bw_i[1].peakTotalVol*8, bw_i[1].peakUpTotalVol*8, bw_i[1].peakDnTotalVol*8, bw_i[1].totalVol, bw_i[1].upTotalVol, bw_i[1].dnTotalVol, bw_i[1].avgTotalBw, bw_i[1].avgUpBw, bw_i[1].avgDnBw,
			bw_i[2].peakTotalVol*8, bw_i[2].peakUpTotalVol*8, bw_i[2].peakDnTotalVol*8,bw_i[2].totalVol, bw_i[2].upTotalVol, bw_i[2].dnTotalVol, bw_i[2].avgTotalBw, bw_i[2].avgUpBw, bw_i[2].avgDnBw,
			bw_i[3].peakTotalVol*8, bw_i[3].peakUpTotalVol*8, bw_i[3].peakDnTotalVol*8,bw_i[3].totalVol, bw_i[3].upTotalVol, bw_i[3].dnTotalVol, bw_i[3].avgTotalBw, bw_i[3].avgUpBw, bw_i[3].avgDnBw,
			bw_i[4].peakTotalVol*8, bw_i[4].peakUpTotalVol*8, bw_i[4].peakDnTotalVol*8,bw_i[4].totalVol, bw_i[4].upTotalVol, bw_i[4].dnTotalVol, bw_i[4].avgTotalBw, bw_i[4].avgUpBw, bw_i[4].avgDnBw,
			bw_i[5].peakTotalVol*8, bw_i[5].peakUpTotalVol*8, bw_i[5].peakDnTotalVol*8,bw_i[5].totalVol, bw_i[5].upTotalVol, bw_i[5].dnTotalVol, bw_i[5].avgTotalBw, bw_i[5].avgUpBw, bw_i[5].avgDnBw,
			bw_i[6].peakTotalVol*8, bw_i[6].peakUpTotalVol*8, bw_i[6].peakDnTotalVol*8,bw_i[6].totalVol, bw_i[6].upTotalVol, bw_i[6].dnTotalVol, bw_i[6].avgTotalBw, bw_i[6].avgUpBw, bw_i[6].avgDnBw,
			bw_i[7].peakTotalVol*8, bw_i[7].peakUpTotalVol*8, bw_i[7].peakDnTotalVol*8,bw_i[7].totalVol, bw_i[7].upTotalVol, bw_i[7].dnTotalVol, bw_i[7].avgTotalBw, bw_i[7].avgUpBw, bw_i[7].avgDnBw);

}

void SpectaProbe::openBwCsvXdrFile(uint16_t &currentMin, uint16_t &currentHour, uint16_t &currentDay, uint16_t &currentMonth, uint16_t &currentYear)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d.csv",
					Global::XDR_DIR.c_str(),
					"bw",
					"bw",
					currentYear,
					currentMonth,
					currentDay,
					currentHour,
					currentMin);
	BwXdrHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void SpectaProbe::writeBwXdr(char *buffer)
{
	TheLog_nc_v1(Log::Info, name(),"    Writing BW           [%s]", buffer);
	BwXdrHandler << buffer << std::endl;
}

void SpectaProbe::closeBwCsvXdrFile()
{ BwXdrHandler.close(); }
