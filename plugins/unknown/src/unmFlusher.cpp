/*
 * UnFlusher.cpp
 *
 *  Created on: 16-Aug-2021
 *      Author: singh
 */

#include "unmFlusher.h"

unmFlusher::unmFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "unmFlusher";
	this->setLogLevel(Log::theLog().level());

	this->instanceId	 = id;
	this->repoInitStatus = false;
	this->curIndex		 = 0;
	this->lastIndex		 = 0;
	this->totalCnt		 = 0;
	this->pFlUtility	 = new flusherUtility(1);
}

unmFlusher::~unmFlusher()
{ delete(this->pFlUtility); }

bool unmFlusher::isInitialized()
{ return repoInitStatus; }

void unmFlusher::run()
{
	repoInitStatus = true;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::UNM_FLUSHER_RUNNING_STATUS[instanceId])
	{
		usleep(Global::SLEEP_TIME);
		curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastIndex != curIndex)
		{
			processTcpData(lastIndex);
			processUdpData(lastIndex);
			processDnsData(lastIndex);

			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, Global::TIME_INDEX);
		}
	}
	printf("  UnMapped Flusher Stopped... \n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void unmFlusher::processTcpData(uint16_t idx)
{
	openXdrFile(PACKET_IPPROTO_TCP, Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::UNM_SESSION_MANAGER_INSTANCES; sm++)
		flushTcpData(flusherStore::utcpCnt[instanceId][sm][idx], flusherStore::utcp[instanceId][sm][idx]);

	closeXdrFile(PACKET_IPPROTO_TCP);
}

void unmFlusher::processUdpData(uint16_t idx)
{
	openXdrFile(PACKET_IPPROTO_UDP, Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::UNM_SESSION_MANAGER_INSTANCES; sm++)
		flushUdpData(flusherStore::uudpCnt[instanceId][sm][idx], flusherStore::uudp[instanceId][sm][idx]);

	closeXdrFile(PACKET_IPPROTO_UDP);
}

void unmFlusher::processDnsData(uint16_t idx)
{
	openXdrFile(PACKET_IPPROTO_DNS, Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::UNM_SESSION_MANAGER_INSTANCES; sm++)
		flushDnsData(flusherStore::udnsCnt[instanceId][sm][idx], flusherStore::udns[instanceId][sm][idx]);

	closeXdrFile(PACKET_IPPROTO_DNS);
}

void unmFlusher::flushTcpData(uint32_t &flCnt, std::unordered_map<uint32_t, tcpSession> &pkt)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createTcpXdrData(&pkt[cnt]))
			{
				tcpXdrHandler << std::string(tcpXdr) << endl;
			}
			pkt.erase(cnt);
			flCnt--;
		}
		pkt.clear();
	}
	flCnt = 0;
}

void unmFlusher::flushUdpData(uint32_t &flCnt, std::unordered_map<uint32_t, udpSession> &pkt)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createUdpXdrData(&pkt[cnt]))
			{
				udpXdrHandler << std::string(udpXdr) << endl;
			}
			pkt.erase(cnt);
			flCnt--;
		}
		pkt.clear();
	}
	flCnt = 0;
}

void unmFlusher::flushDnsData(uint32_t &flCnt, std::unordered_map<uint32_t, dnsSession> &pkt)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createDnsXdrData(&pkt[cnt]))
			{
				dnsXdrHandler << std::string(dnsXdr) << endl;
			}
			pkt.erase(cnt);
			flCnt--;
		}
		pkt.clear();
	}
	flCnt = 0;
}

bool unmFlusher::createTcpXdrData(tcpSession *pTcpSession)
{
	if(pTcpSession == NULL)
		return false;

	tcpXdr[0] = 0;
	buildTcpXdr(pTcpSession);

	if(strlen(tcpXdr) <= 0)
		return false;
	else
		return true;
}

bool unmFlusher::createUdpXdrData(udpSession *pUdpSession)
{
	udpXdr[0] = 0;
	buildUdpXdr(pUdpSession);

	if(strlen(udpXdr) <= 0)
		return false;
	else
		return true;
}

bool unmFlusher::createDnsXdrData(dnsSession *pDnsSession)
{
	dnsXdr[0] = 0;
	pFlUtility->buildDnsXdr(pDnsSession, dnsXdr);

	if(strlen(dnsXdr) <= 0)
		return false;
	else
		return true;
}

void unmFlusher::buildTcpXdr(tcpSession *pTcpSession)
{
	string url = "";
	string sessionKey = "";

	sIpAddress[0] = 0;
	dIpAddress[0] = 0;

	/* get URL */
	switch(pTcpSession->ipVer)
	{
		case IPVersion4:
						sessionKey = to_string(pTcpSession->ipV4sessionKey);

						dnsData::getUrl(url, pTcpSession->dIpv4);

						long2Ip(pTcpSession->sIpv4, sIpAddress);
						long2Ip(pTcpSession->dIpv4, dIpAddress);


						break;
		default:
			break;
	}

		sprintf(tcpXdr, "%d,%d,%d,%s,"	// 01 - Probe Id			02 - XDR Id, 		     03 - Protocol Type		04 - Protocol Desc,
					 "%d,%s-%d,"		// 05 - Dest Port	    	06 - Session Key-Slice Counter
					 "%s,%d,%s,%d,"		// 08 - Source Ip			09 - Source Port		 10 - Dest Ip			11 - Dest Port,
					 "%d,%d,%u,"		// 12 - VLAN Id				13 - Frame Cnt			 14 - Frame Size
					 "%d,%u,"			// 15 - Payload Pkt   		16 - Payload Size
					 "%lu,%lu,"			// 17 - Start Time			18 - End Time
					 "%d,%s,%d",		// 19 - Cause Code			20 - URL				 21 - Ip version

				Global::PROBE_ID, IP_XDR_ID, pTcpSession->protocolType, initalize::protocolName[pTcpSession->protocolType].c_str(),
				pTcpSession->dPort, sessionKey.c_str(), pTcpSession->sliceCounter,
				sIpAddress, pTcpSession->sPort, dIpAddress, pTcpSession->dPort,
				0, pTcpSession->frCount, pTcpSession->frSize,
				pTcpSession->pLoadPkt, pTcpSession->pLoadSize,
				pTcpSession->startTimeEpochNanoSec, pTcpSession->endTimeEpochNanoSec,
				pTcpSession->causeCode, url.c_str(), pTcpSession->ipVer);
}

void unmFlusher::buildUdpXdr(udpSession *pUdpSession)
{
	string url = "";

	string sessionKey = "";
	sIpAddress[0] = 0;
	dIpAddress[0] = 0;

	/* get URL */
	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
						sessionKey = to_string(pUdpSession->ipV4sessionKey);

						dnsData::getUrl(url, pUdpSession->dIpv4);

						long2Ip(pUdpSession->sIpv4, sIpAddress);
						long2Ip(pUdpSession->sIpv4, dIpAddress);
						break;
		default:
			break;
	}

		sprintf(udpXdr, "%d,%d,%d,%s,"	// 01 - Probe Id			02 - XDR Id, 		     03 - Protocol Type		04 - Protocol Desc,
					 "%d,%s-%d,"		// 05 - Dest Port	    	06 - Session Key-Slice Counter
					 "%s,%d,%s,%d,"		// 08 - Source Ip			09 - Source Port		 10 - Dest Ip			11 - Dest Port,
					 "%d,%d,%u,"		// 12 - VLAN Id				13 - Frame Cnt			 14 - Frame Size
					 "%d,%u,"			// 15 - Payload Pkt   		16 - Payload Size
					 "%lu,%lu,"			// 17 - Start Time			18 - End Time
					 "%d,%s,%d",		// 19 - Cause Code			20 - URL				 21 - Ip version

				Global::PROBE_ID, IP_XDR_ID, pUdpSession->protocolType, initalize::protocolName[pUdpSession->protocolType].c_str(),
				pUdpSession->dPort, sessionKey.c_str(), pUdpSession->sliceCounter,
				sIpAddress, pUdpSession->sPort, dIpAddress, pUdpSession->dPort,
				0, pUdpSession->frCount, pUdpSession->frSize,
				pUdpSession->pLoadPkt, pUdpSession->pLoadSize,
				pUdpSession->startTimeEpochNanoSec, pUdpSession->endTimeEpochNanoSec,
				pUdpSession->causeCode, url.c_str(), pUdpSession->ipVer);
}

void unmFlusher::openXdrFile(uint16_t protocol, uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	switch(protocol)
	{
		case PACKET_IPPROTO_TCP:
				sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
								Global::UNKNOWN_XDR_DIR.c_str(),
								"ip",
								"tcp",
								year,
								month,
								day,
								hour,
								min,
								instanceId);
				tcpXdrHandler.open((char *)filePath, ios :: out | ios :: app);
				break;

		case PACKET_IPPROTO_UDP:
				sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
								Global::UNKNOWN_XDR_DIR.c_str(),
								"ip",
								"udp",
								year,
								month,
								day,
								hour,
								min,
								instanceId);
				udpXdrHandler.open((char *)filePath, ios :: out | ios :: app);
				break;

		case PACKET_IPPROTO_DNS:
				sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
								Global::UNKNOWN_XDR_DIR.c_str(),
								"dns",
								"dns",
								year,
								month,
								day,
								hour,
								min,
								instanceId);
				dnsXdrHandler.open((char *)filePath, ios :: out | ios :: app);
				break;
	}
}

void unmFlusher::closeXdrFile(uint16_t protocol)
{
	switch(protocol)
	{
		case PACKET_IPPROTO_TCP:
				tcpXdrHandler.close();
				break;

		case PACKET_IPPROTO_UDP:
				udpXdrHandler.close();
				break;

		case PACKET_IPPROTO_DNS:
				dnsXdrHandler.close();
				break;
	}
}
