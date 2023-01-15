/*
 * dnsFlusher.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "dnsFlusher.h"

dnsFlusher::dnsFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "dnsFlusher";
	this->setLogLevel(Log::theLog().level());

	this->instanceId = id;
	this->lastIndex		= 0;
	this->curIndex		= 0;
	this->readyFlag		= false;
	this->totalCnt		= 0;
	this->dnsXdr[0]		= 0;

	pFlUtility = new flusherUtility(1);
}

dnsFlusher::~dnsFlusher()
{ delete(pFlUtility); }

bool dnsFlusher::isInitialized()
{ return readyFlag; }

void dnsFlusher::run()
{
	readyFlag = true;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC ,Global::TIME_INDEX);

	while(Global::DNS_FLUSHER_RUNNING_STATUS[this->instanceId])
	{
		usleep(Global::SLEEP_TIME);
		curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastIndex != curIndex)
		{
			strcpy(dnsXdr, "");
			processDnsData(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, Global::TIME_INDEX);
		}
	}
	printf("  Dns Flusher [%02d] Stopped... \n", this->instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);

}

void dnsFlusher::processDnsData(uint16_t idx)
{
	openDnsXdrFile(Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::UDP_SESSION_MANAGER_INSTANCES; sm++)
		flushData(flusherStore::dnsCnt[instanceId][sm][idx], flusherStore::dns[instanceId][sm][idx]);

	closeDnsXdrFile();
}

void dnsFlusher::flushData(uint32_t &flCnt, std::unordered_map<uint32_t, dnsSession> &pkt)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createXdrData(&pkt[cnt]))
			{
				xdrDnsHandler << std::string(dnsXdr) << endl;
			}
			pkt.erase(cnt);
			flCnt--;
		}
		pkt.clear();
	}
	flCnt = 0;
}

bool dnsFlusher::createXdrData(dnsSession *pDnsSession)
{
	if(pDnsSession == NULL)
		return false;

	dnsXdr[0] = 0;
	pFlUtility->buildDnsXdr(pDnsSession, dnsXdr);

	if(strlen(dnsXdr) <= 0)
		return false;
	else
		return true;
}

void dnsFlusher::openDnsXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%d_%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
					Global::XDR_DIR.c_str(),
					"dns",
					Global::PROBE_ID, "dns",
					year,
					month,
					day,
					hour,
					min,
					instanceId);
	xdrDnsHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void dnsFlusher::closeDnsXdrFile()
{ xdrDnsHandler.close(); }
