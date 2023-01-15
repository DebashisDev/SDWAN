/*
 * ProbeStats.cpp
 *
 *  Created on: Feb 1, 2017
 *      Author: Debashis
 */

#include <ctime>
#include "ProbeStats.h"

ProbeStats::ProbeStats()
{
	this->_name = "ProbeStats";
	this->setLogLevel(Log::theLog().level());
}

ProbeStats::~ProbeStats()
{ }

void ProbeStats::run()
{
	uint16_t dd = 0, hh = 0, mm = 0, ss = 0;
	uint16_t printloopCnt 	= 0;
	char buffer[80];
	long startTime 		= 0;
	long runTime 		= 0;

	gettimeofday(&curTime, NULL);
	startTime = curTime.tv_sec;

	bool statsState = false;

	while(Global::PROBE_STATS_RUNNING_STATUS)
	{
	  sleep(1);

	  if(Global::PRINT_STATS_FREQ_SEC > 0 && Global::PRINT_STATS)
	  {
	  	printloopCnt++;

	  	gettimeofday(&curTime, NULL);
	  	now_tm = localtime(&curTime.tv_sec);
	  	runTime = curTime.tv_sec - startTime;

	  	dd = (int)(runTime / 84600);
	  	hh = (int)((runTime - (dd * 84600)) / 3600);
	  	mm = (int)((runTime - ((dd * 84600) + (hh * 3600))) / 60);
	  	ss = (int)(runTime - ((dd * 84600) + (hh * 3600) + (mm * 60)));
	  	sprintf(buffer, "%03d:%02d:%02d",dd,hh,mm);

	  	if(printloopCnt >= Global::PRINT_STATS_FREQ_SEC)
	  	{
	  		printloopCnt = 0;
	  		printInterfaceStats(buffer);
	  		printf("\n\n");
	  	}
	  }
	}
	printf("  ProbeStats Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}


void ProbeStats::printInterfaceStats(char *runTime)
{
	uint16_t ti;

	  printf("\n   %s   [%02d:%02d]         PPS       BW                       T0       T1       T2       T3       T4       T5       T6       T7       T8       T9\n", runTime, now_tm->tm_hour,now_tm->tm_min);

	  for(int intf = 0; intf < Global::NO_OF_INTERFACES; intf ++)
	  {
		  printf("         Interface [%6s]   %08d  %06d             ", Global::PNAME[intf].c_str(), Global::PKT_RATE_INTF[intf], Global::BW_MBPS_INTF[intf]);
		  printf("   ");
		  for(int router = 0; router < Global::ROUTER_PER_INTERFACE[intf]; router++)
		  {
			for(ti = 0; ti < 10; ti++)
				printf("  %07d", PKTStore::cnt[intf][router][ti]);

			printf("\n");
			printf("                                                              ");
		  }
			printf("\n");
	  }

	  printTcpStoreStats();
	  printUdpStoreStats();
	  printDnsStoreStats();
	  printIpXdrFlushStats();
}


void ProbeStats::printTcpStoreStats()
{
	uint16_t i = 0;
	uint32_t t_cnt[10];

	for(i = 0; i < 10; i++)
		t_cnt[i] = 0;

	for(uint16_t sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
	{
		printf("                    Tcp %07d (%07d %07d) sm[%02d]    ->",
				(IPStats::smTcpV4SessionCnt[sm] + IPStats::smTcpV6SessionCnt[sm]), IPStats::smTcpV4SessionScan[sm] + IPStats::smTcpV6SessionScan[sm], IPStats::smTcpV4SessionClean[sm] + IPStats::smTcpV6SessionClean[sm], sm);

		for(i=0; i<10; i++)
		{
			for(int j = 0; j < Global::NO_OF_INTERFACES; j++)
				for(int k = 0; k < Global::ROUTER_PER_INTERFACE[j]; k++)
					t_cnt[i] += SmStore::tcpCnt[sm][j][k][i];

			printf("  %07d",	t_cnt[i]);
			t_cnt[i] = 0;
		}
		printf("\n");
	}
	printf("\n");
}

void ProbeStats::printUdpStoreStats()
{
	uint16_t i = 0;
	uint32_t t_cnt[10];

	for(i = 0; i < 10; i++)
		t_cnt[i] = 0;

	for(uint16_t sm = 0; sm < Global::UDP_SESSION_MANAGER_INSTANCES; sm++)
	{
		printf("                    Udp %07d (%07d %07d) sm[%02d]    ->",
				(IPStats::smUdpV4SessionCnt[sm] + IPStats::smUdpV6SessionCnt[sm]), IPStats::smUdpV4SessionScan[sm] + IPStats::smUdpV6SessionScan[sm], IPStats::smUdpV4SessionClean[sm] + IPStats::smUdpV6SessionClean[sm], sm);

		for(i=0; i<10; i++)
		{
			for(int j = 0; j < Global::NO_OF_INTERFACES; j++)
				for(int k = 0; k < Global::ROUTER_PER_INTERFACE[j]; k++)
					t_cnt[i] += SmStore::udpCnt[sm][j][k][i];

			printf("  %07d",	t_cnt[i]);
			t_cnt[i] = 0;
		}
		printf("\n");
	}
	printf("\n");
}

void ProbeStats::printDnsStoreStats()
{
	uint16_t i = 0;
	uint32_t t_cnt[10];

	for(i = 0; i < 10; i++)
		t_cnt[i] = 0;

	for(uint16_t sm = 0; sm < Global::DNS_SESSION_MANAGER_INSTANCES; sm++)
	{
		printf("                    Dns %07d (%07d %07d) sm[%02d]    ->",
				(IPStats::smDnsV4SessionCnt[sm] + IPStats::smDnsV6SessionCnt[sm]), IPStats::smDnsV4SessionScan[sm] + IPStats::smDnsV6SessionScan[sm], IPStats::smDnsV4SessionClean[sm] + IPStats::smDnsV6SessionClean[sm], sm);

		for(i=0; i<10; i++)
		{
			for(int j = 0; j < Global::NO_OF_INTERFACES; j++)
				for(int k = 0; k < Global::ROUTER_PER_INTERFACE[j]; k++)
					t_cnt[i] += SmStore::dnsCnt[sm][j][k][i];

			printf("  %07d",	t_cnt[i]);
			t_cnt[i] = 0;
		}
		printf("\n");
	}
	printf("\n");
}


void ProbeStats::printIpXdrFlushStats()
{
	uint16_t fId, sId, tId;
	uint32_t t_cnt[10];

	for(uint16_t i = 0; i < 10; i++)
		t_cnt[i] = 0;

	if(Global::IP_WRITE_XDR)
	{
		printf("\n                                            TCP XDR Flush ->  ");
		for(tId = 0; tId < 10; tId++) {
			for(fId = 0; fId < Global::NO_OF_TCP_FLUSHER; fId++)
				for(sId = 0; sId < Global::TCP_SESSION_MANAGER_INSTANCES; sId++)
						t_cnt[tId] += flusherStore::tcpCnt[fId][sId][tId];

			printf("  %07d",	t_cnt[tId]);
			t_cnt[tId] = 0;
		}
	}

	for(uint16_t i = 0; i < 10; i++)
		t_cnt[i] = 0;

	if(Global::IP_WRITE_XDR)
	{
		printf("\n                                            UDP XDR Flush ->  ");

		for(tId = 0; tId < 10; tId++) {
			for(fId = 0; fId < Global::NO_OF_UDP_FLUSHER; fId++)
				for(sId = 0; sId < Global::UDP_SESSION_MANAGER_INSTANCES; sId++)
					t_cnt[tId] += flusherStore::udpCnt[fId][sId][tId];

			printf("  %07d",	t_cnt[tId]);
			t_cnt[tId] = 0;
		}
	}

	if(Global::DNS_WRITE_XDR)
	{
		printf("\n                                            DNS XDR Flush ->  ");

		for(fId = 0; fId < Global::NO_OF_DNS_FLUSHER; fId++)
			for(sId = 0; sId < Global::DNS_SESSION_MANAGER_INSTANCES; sId++)
				for(tId = 0; tId < 10; tId++)
					printf("  %07d", (flusherStore::dnsCnt[fId][sId][tId]));
	}

	if(Global::UNM_WRITE_XDR)
	{
		printf("\n                                    UNMAPPED IP XDR Flush ->  ");

		for(fId = 0; fId < Global::NO_OF_UNM_FLUSHER; fId++)
			for(sId = 0; sId < Global::UNM_SESSION_MANAGER_INSTANCES; sId++)
				for(tId = 0; tId < 10; tId++)
					printf("  %07d", flusherStore::utcpCnt[fId][sId][tId] + flusherStore::uudpCnt[fId][sId][tId] + flusherStore::udnsCnt[fId][sId][tId]);
	}
	printf("\n");
}
