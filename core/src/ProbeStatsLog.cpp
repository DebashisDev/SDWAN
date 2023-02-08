/*
 * ProbeStatsLog.cpp
 *
 *  Created on: Jul 21, 2017
 *      Author: Debashis
 */

#include <ctime>
#include "ProbeStatsLog.h"

ProbeStatsLog::ProbeStatsLog()
{
	this->_name = "ProbeStatsLog";
	this->setLogLevel(Log::theLog().level());

	this->nicCounter 		= 0;
	this->solCounter 		= 0;
	this->interfaceCounter = 0;
}

ProbeStatsLog::~ProbeStatsLog()
{}

void ProbeStatsLog::run()
{
	uint16_t		printloopCnt = 0, dd = 0, hh = 0, mm = 0, ss = 0;
	long 	startTime = 0, runTime = 0, currentHH = 0;
	char 	buffer[80];
	bool 	logStatsStatus = false;

	struct tm *now_tm;

	gettimeofday(&curTime, NULL);
	startTime = curTime.tv_sec;

	for(nicCounter = 0; nicCounter < Global::NO_OF_NIC_INTERFACE; nicCounter++)
		INTERFACES_NAME[nicCounter] = Global::ETHERNET_INTERFACES[nicCounter];

	interfaceCounter = nicCounter;

	while(Global::PROBE_STATS_RUNNING_STATUS)
	{
		  sleep(1);
		  printloopCnt++;

		  gettimeofday(&curTime, NULL);
		  runTime = curTime.tv_sec - startTime;

		  dd = (int)(runTime / 84600);
		  hh = (int)((runTime - (dd * 84600)) / 3600);
		  mm = (int)((runTime - ((dd * 84600) + (hh * 3600))) / 60);
		  ss = (int)(runTime - ((dd * 84600) + (hh * 3600) + (mm * 60)));
		  sprintf(buffer, "%03d:%03d:%03d:%03d", dd, hh, mm, ss);

		  if(printloopCnt >= Global::LOG_STATS_FREQ_SEC)
		  {
			  printloopCnt = 0;
			  printInterfaceStats(buffer);
		  }
	}

	printf("  Probe Log Stats Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void ProbeStatsLog::printInterfaceStats(char *runTime)
{
	  TheLog_nc_v1(Log::Info, name(),"", "");

	  for(int intf = 0; intf < Global::NO_OF_INTERFACES; intf++)
	  {
		  TheLog_nc_v5(Log::Info, name(),"   Interface   [%6s] [%s] %08d PPS  %06d Mbps | Packet Rejected %011lu",
				  INTERFACES_NAME[intf].c_str(), runTime, Global::PKT_RATE_INTF[intf], Global::BW_MBPS_INTF[intf], Global::DISCARDED_PACKETS[intf]);

		  char buffer[500];
		  buffer[0] = 0;

		  for(uint16_t router = 0; router < Global::ROUTER_PER_INTERFACE[intf]; router++)
		  {
			  uint16_t rCount = 0;

			  for(uint16_t ti = 0; ti < 10; ti++)
				rCount += PKTStore::cnt[intf][router][ti];

			  if(router == 0)
				  sprintf(buffer, "%07d", rCount);
			  else
				  sprintf(buffer, "%s  %07d",buffer, rCount);
		  }

		  TheLog_nc_v2(Log::Info, name(), "   Interface(R)[%6s] %s", INTERFACES_NAME[intf].c_str(), buffer);
	  }

	  printPacketCounter();
	  printDnsLookup();

	  printTcpCleanUpStats();
	  printUdpCleanUpStats();
	  printDnsCleanUpStats();
	  printUnmCleanUpStats();
}

void ProbeStatsLog::printPacketCounter()
{
	uint64_t	tcpCnt = 0;
	uint64_t	udpCnt = 0;
	uint64_t	dnsCnt = 0;
	uint64_t	aaaCnt = 0;

	uint64_t	smtcpCnt = 0;
	uint64_t	smudpCnt = 0;
	uint64_t	smdnsCnt = 0;
	uint64_t	smaaaCnt = 0;

	uint64_t	unCnt = 0;

	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
	{
		for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; i++)
		{
			tcpCnt += Global::TCP_PACKETS_PER_DAY[i][r];
			udpCnt += Global::UDP_PACKETS_PER_DAY[i][r];
			dnsCnt += Global::DNS_PACKETS_PER_DAY[i][r];
		}
	}

	for(uint16_t i = 0; i < Global::TCP_SESSION_MANAGER_INSTANCES; i++)
	{
		smtcpCnt += Global::SM_TCP_PACKETS_PER_DAY[i];
		smudpCnt += Global::SM_UDP_PACKETS_PER_DAY[i];
		smdnsCnt += Global::SM_DNS_PACKETS_PER_DAY[i];
		unCnt += Global::SM_UN_PACKETS_PER_DAY[i];
	}

	TheLog_nc_v4(Log::Info, name(), "   Packet Received TCP: %12lu| UDP: %12lu| DNS: %12lu| AAA: %12lu", tcpCnt, udpCnt, dnsCnt, aaaCnt);
	TheLog_nc_v5(Log::Info, name(), "   SM     Received TCP: %12lu| UDP: %12lu| DNS: %12lu| AAA: %12lu| UN: %12lu", smtcpCnt, smudpCnt, smdnsCnt, smaaaCnt, unCnt);
	TheLog_nc_v1(Log::Info, name(), "%s", "");
}

void ProbeStatsLog::printDnsLookup()
{
	uint32_t dnsLookupStoreCnt = 0;

	for(uint16_t counter = 0; counter < 10; counter ++)
		dnsLookupStoreCnt += DNSGlobal::dnsLookUpMap[counter].size();

	TheLog_nc_v2(Log::Info, name(),"   DnsLookUp Size       IPv4: %012u | IPv6: %012u", dnsLookupStoreCnt, DNSGlobal::dnsV6LookUpMap.size());
}

void ProbeStatsLog::printTcpCleanUpStats()
{
	char buffer[500];

	uint32_t totalTcpV4Session, totalTcpV6Session;
	uint32_t totalDnsV4Session, totalDnsV6Session;
	uint32_t tcpV4Scan, tcpV6Scan;
	uint32_t tcpV4Clean, tcpV6Clean;

	totalDnsV4Session = totalDnsV6Session = 0;
	tcpV4Scan = tcpV6Scan = 0;
	tcpV4Clean = tcpV6Clean = 0;

	for(uint16_t sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
	{
		totalTcpV4Session += IPStats::smTcpV4SessionCnt[sm];
		totalTcpV6Session += IPStats::smTcpV6SessionCnt[sm];

		tcpV4Scan += IPStats::smTcpV4SessionScan[sm];
		tcpV6Scan += IPStats::smTcpV6SessionScan[sm];

		tcpV4Clean += IPStats::smTcpV4SessionClean[sm];
		tcpV6Clean += IPStats::smTcpV6SessionClean[sm];
	}

	TheLog_nc_v4(Log::Info, name(), "   TCP [%02d] Sessions     %012u  Ipv4 %012u| Ipv6 %012u", Global::TCP_SESSION_MANAGER_INSTANCES, totalTcpV4Session + totalTcpV6Session, totalTcpV4Session, totalTcpV6Session);
	TheLog_nc_v3(Log::Info, name(), "                Scan    %012u  Ipv4 %012u| Ipv6 %012u", (tcpV4Scan + tcpV6Scan), tcpV4Scan, tcpV6Scan);
	TheLog_nc_v3(Log::Info, name(), "               Clean    %012u  Ipv4 %012u| Ipv6 %012u", (tcpV4Clean + tcpV6Clean), tcpV4Clean, tcpV6Clean);
	TheLog_nc_v1(Log::Info, name(), "%s", "");
}

void ProbeStatsLog::printUdpCleanUpStats()
{
	char buffer[500];

	uint32_t totalUdpV4Session, totalUdpV6Session;
	uint32_t udpV4Scan, udpV6Scan;
	uint32_t udpV4Clean, udpV6Clean;

	udpV4Scan = udpV6Scan = 0;
	udpV4Clean = udpV6Clean = 0;

	for(uint16_t sm = 0; sm < Global::UDP_SESSION_MANAGER_INSTANCES; sm++)
	{
		totalUdpV4Session += IPStats::smUdpV4SessionCnt[sm];
		totalUdpV6Session += IPStats::smUdpV6SessionCnt[sm];

		udpV4Scan += IPStats::smUdpV4SessionScan[sm];
		udpV6Scan += IPStats::smUdpV6SessionScan[sm];

		udpV4Clean += IPStats::smUdpV4SessionClean[sm];
		udpV6Clean += IPStats::smUdpV6SessionClean[sm];
	}

	TheLog_nc_v4(Log::Info, name(), "   UDP [%02d] Sessions     %012u  Ipv4 %012u| Ipv6 %012u", Global::UDP_SESSION_MANAGER_INSTANCES, totalUdpV4Session + totalUdpV6Session, totalUdpV4Session, totalUdpV6Session);
	TheLog_nc_v3(Log::Info, name(), "                Scan    %012u  Ipv4 %012u| Ipv6 %012u", (udpV4Scan + udpV6Scan), udpV4Scan, udpV6Scan);
	TheLog_nc_v3(Log::Info, name(), "               Clean    %012u  Ipv4 %012u| Ipv6 %012u", (udpV4Clean + udpV6Clean), udpV4Clean, udpV6Clean);
	TheLog_nc_v1(Log::Info, name(), "%s", "");
}

void ProbeStatsLog::printDnsCleanUpStats()
{
	char buffer[500];

	uint32_t totalDnsV4Session, totalDnsV6Session;
	uint32_t dnsV4Scan, dnsV6Scan;
	uint32_t dnsV4Clean, dnsV6Clean;

	dnsV4Scan = dnsV6Scan = 0;
	dnsV4Clean = dnsV6Clean = 0;

	for(uint16_t sm = 0; sm < Global::DNS_SESSION_MANAGER_INSTANCES; sm++)
	{
		totalDnsV4Session += IPStats::smDnsV4SessionCnt[sm];
		totalDnsV6Session += IPStats::smDnsV6SessionCnt[sm];

		dnsV4Scan += IPStats::smDnsV4SessionScan[sm];
		dnsV6Scan += IPStats::smDnsV6SessionScan[sm];

		dnsV4Clean += IPStats::smDnsV4SessionClean[sm];
		dnsV6Clean += IPStats::smDnsV6SessionClean[sm];
	}

	TheLog_nc_v4(Log::Info, name(), "   DNS [%02d] Sessions     %012u  Ipv4 %012u| Ipv6 %012u", Global::DNS_SESSION_MANAGER_INSTANCES, totalDnsV4Session + totalDnsV6Session, totalDnsV4Session, totalDnsV6Session);
	TheLog_nc_v3(Log::Info, name(), "                Scan    %012u  Ipv4 %012u| Ipv6 %012u", (dnsV4Scan + dnsV6Scan), dnsV4Scan, dnsV6Scan);
	TheLog_nc_v3(Log::Info, name(), "               Clean    %012u  Ipv4 %012u| Ipv6 %012u", (dnsV4Clean + dnsV6Clean), dnsV4Clean, dnsV6Clean);
	TheLog_nc_v1(Log::Info, name(), "%s", "");
}

void ProbeStatsLog::printUnmCleanUpStats()
{
	char buffer[500];

	uint32_t totalUnmV4Session = 0;
	uint32_t aaaV4Scan = 0;
	uint32_t aaaV4Clean = 0;

	for(uint16_t sm = 0; sm < Global::UNM_SESSION_MANAGER_INSTANCES; sm++)
	{
		totalUnmV4Session += IPStats::smUnTcpSessionCnt[sm] + IPStats::smUnUdpSessionCnt[sm];
		aaaV4Scan += IPStats::smUnTcpSessionScan[sm] + IPStats::smUnUdpSessionScan[sm];
		aaaV4Clean += IPStats::smUnTcpSessionClean[sm] + IPStats::smUnUdpSessionClean[sm];
	}

	TheLog_nc_v4(Log::Info, name(), "   UNM [%02d] Sessions     %012u  Ipv4 %012u| Ipv6 %012u", Global::UNM_SESSION_MANAGER_INSTANCES, totalUnmV4Session, totalUnmV4Session, 0);
	TheLog_nc_v3(Log::Info, name(), "                Scan    %012u  Ipv4 %012u| Ipv6 %012u", aaaV4Scan, aaaV4Scan, 0);
	TheLog_nc_v3(Log::Info, name(), "               Clean    %012u  Ipv4 %012u| Ipv6 %012u", aaaV4Clean, aaaV4Clean, 0);
	TheLog_nc_v1(Log::Info, name(), "%s", "");
}
