/*
 * udpFlusher.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "udpFlusher.h"

udpFlusher::udpFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "udpFlusher";
	this->setLogLevel(Log::theLog().level());

	this->instanceId = id;
	this->totalCnt = 0;
	this->initStatus = false;
	this->lastTidx = 0;
	this->curTidx = 0;
	this->fUtil = new flusherUtility(this->instanceId);
}

udpFlusher::~udpFlusher()
{ delete (fUtil); }

bool udpFlusher::isInitialized()
{ return initStatus; }

void udpFlusher::run()
{
	initStatus = true;
	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::UDP_FLUSHER_RUNNING_STATUS[this->instanceId])
	{
		usleep(Global::SLEEP_TIME);
		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastTidx != curTidx)
		{
			strcpy(udpXdr, "");
			processUdpData(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx, Global::TIME_INDEX);
		}
	}
	printf("  UDP Flusher Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);

}

void udpFlusher::processUdpData(uint16_t tIdx)
{
	openUdpXdrFile(Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::UDP_SESSION_MANAGER_INSTANCES; sm ++)
		getUdpData(flusherStore::udpCnt[instanceId][sm][tIdx], flusherStore::udp[instanceId][sm][tIdx]);

	closeUdpXdrFile();
}

void udpFlusher::getUdpData(uint32_t &flCnt, std::unordered_map<uint32_t, udpSession> &fStore)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createUdpXdrData(&fStore[cnt]))
			{ xdrUdpHandler << std::string(udpXdr) << endl; }

			fStore.erase(cnt);
			flCnt--;
		}
		fStore.clear();
	}
	flCnt = 0;
}

bool udpFlusher::createUdpXdrData(udpSession *pUdpSession)
{
	if(pUdpSession == NULL)
		return false;

	udpXdr[0] = 0;
	fUtil->buildUdpXdr(pUdpSession, udpXdr);

	if(strlen(udpXdr) <= 0)
		return false;
	else
		return true;
}

void udpFlusher::openUdpXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%d_%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
					Global::XDR_DIR.c_str(),
					"ip",
					Global::PROBE_ID,"udp",
					year,
					month,
					day,
					hour,
					min,
					instanceId);
	xdrUdpHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void udpFlusher::closeUdpXdrFile()
{ xdrUdpHandler.close(); }
