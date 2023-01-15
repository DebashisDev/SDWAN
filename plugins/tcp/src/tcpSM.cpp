/*
 * IPSessionManager.cpp
 *
 *  Created on: Apr 24, 2017
 *      Author: Debashis
 */

#include "tcpSM.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

tcpSM::tcpSM(uint16_t id)
{
	this->_name = "tcpSM";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 	= id;
	this->initStats 	= false;
	this->lastTidx		= 0;
	this->curTidx		= 0;
	this->curIndexClnUp	= 0;
	this->lastIndexClnUp= 0;
	this->pTcpSMInterface	= new tcpSMInterface(id);
}

tcpSM::~tcpSM()
{ delete(pTcpSMInterface); }

bool tcpSM::isInitialized()
{ return initStats; }

void tcpSM::run()
{
	initStats = true;
	curIndexClnUp = lastIndexClnUp 	= Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::TCP_SESSION_MANAGER_RUNNING_STATUS[instanceId])
	{
		usleep(Global::SLEEP_TIME);

		curIndexClnUp = Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastTidx != curTidx)
		{
			processQueue(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx, Global::TIME_INDEX);
		}

		if(curIndexClnUp != lastIndexClnUp) /* Every Second jobs */
		{
			pTcpSMInterface->sessionTimeOutClean(false);	// IP Cleanup
			lastIndexClnUp = curIndexClnUp;
		}

		executeDayEndActivity();

	} /* End Of (Main) While Loop */

	printf("  IPSessionManager [%02d] Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void tcpSM::executeDayEndActivity()
{
	/* End of the Day Activity */
	if(Global::CURRENT_HOUR == Global::END_OF_DAY_CLEAN_HOUR && Global::CURRENT_MIN == Global::END_OF_DAY_CLEAN_MIN && Global::CURRENT_SEC == Global::END_OF_DAY_CLEAN_SEC)
	{
		for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
			for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; r++)
				for(uint16_t t = 0; t < 10; t++)
				{
					SmStore::tcpBusy[instanceId][i][r][t] = false;
					SmStore::tcpCnt[instanceId][i][r][t] = 0;
					SmStore::tcpStore[instanceId][i][r][t].clear();
				}

		pTcpSMInterface->sessionTimeOutClean(true);
	}
}

void tcpSM::processQueue(uint16_t t_index)
{
	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
		for(uint16_t k = 0; k < Global::ROUTER_PER_INTERFACE[i]; k++)
			processPackets(SmStore::tcpBusy[instanceId][i][k][t_index], SmStore::tcpCnt[instanceId][i][k][t_index],SmStore::tcpStore[instanceId][i][k][t_index]);
}

void tcpSM::processPackets(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, MPacket> &store)
{
	uint32_t recCnt = cnt;

	if(recCnt > 0)
	{
		busy = true;
		for(uint32_t i = 0; i < recCnt; i++)
		{
			callInterface(&store[i]);
			store.erase(i);
		}
		store.clear();
		cnt = 0;
		busy = false;
	}
}

void tcpSM::callInterface(MPacket *msgObj)
{
	switch(msgObj->pType)
	{
		case PACKET_IPPROTO_TCP:
				Global::SM_TCP_PACKETS_PER_DAY[instanceId]++;
				pTcpSMInterface->packetEntry(msgObj);
				break;

		default:
				break;
	}
}
