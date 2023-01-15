/*
 * IPFlusher.cpp
 *
 *  Created on: Apr 24, 2017
 *      Author: Debashis
 */

#include "tcpFlusher.h"

tcpFlusher::tcpFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "tcpFlusher";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 	= id;
	this->totalCnt 	= 0;
	this->lastTidx		= 0;
	this->curTidx 		= 0;
	this->initStatus 	= false;
	this->fUtil 		= new flusherUtility(this->instanceId);
}

tcpFlusher::~tcpFlusher()
{ delete(fUtil); }

bool tcpFlusher::isInitialized()
{ return initStatus; }

void tcpFlusher::run()
{
	initStatus = true;
	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::TCP_FLUSHER_RUNNING_STATUS[this->instanceId])
	{
		usleep(Global::SLEEP_TIME);
		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastTidx != curTidx)
		{
			processTcpData(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx, Global::TIME_INDEX);
		}
	}
	printf("  TCP Flusher Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);

}

void tcpFlusher::processTcpData(uint16_t tIdx)
{
	openTcpXdrFile(Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::TCP_SESSION_MANAGER_INSTANCES; sm++)
		getTcpData(flusherStore::tcpCnt[instanceId][sm][tIdx], flusherStore::tcp[instanceId][sm][tIdx]);

	closeTcpXdrFile();
}

void tcpFlusher::getTcpData(uint32_t &flCnt, std::unordered_map<uint32_t, tcpSession> &fStore)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for(uint32_t cnt = 0; cnt < totalCnt; cnt++)
		{
			if(createTcpXdrData(&fStore[cnt]))
			{ xdrTcpHandler << std::string(tcpXdr) << endl; }

			fStore.erase(cnt);
			flCnt--;
		}
		fStore.clear();
	}
	flCnt = 0;
}

bool tcpFlusher::createTcpXdrData(tcpSession *pTcpSession)
{
	if(pTcpSession == NULL)
		return false;

	tcpXdr[0] = 0;
	fUtil->buildTcpXdr(pTcpSession, tcpXdr);

	if(strlen(tcpXdr) <= 0)
		return false;
	else
		return true;
}

void tcpFlusher::openTcpXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%d_%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
					Global::XDR_DIR.c_str(),
					"ip",
					Global::PROBE_ID, "tcp",
					year,
					month,
					day,
					hour,
					min,
					instanceId);
	xdrTcpHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void tcpFlusher::closeTcpXdrFile()
{ xdrTcpHandler.close(); }

