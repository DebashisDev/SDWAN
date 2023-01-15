/*
 * udpSM.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "udpSM.h"

udpSM::udpSM(uint16_t id)
{
	this->_name = "udpSM";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->initStats 		= false;
	this->lastTidx			= 0;
	this->curTidx			= 0;
	this->curIndexClnUp		= 0;
	this->lastIndexClnUp	= 0;
	this->pUdpSMInterface	= new udpSMInterface(id);
}

udpSM::~udpSM()
{ delete(pUdpSMInterface); }

bool udpSM::isInitialized()
{ return initStats; }

void udpSM::run()
{
	initStats = true;
	curIndexClnUp = lastIndexClnUp 	= Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::UDP_SESSION_MANAGER_RUNNING_STATUS[instanceId])
	{
		usleep(Global::SLEEP_TIME);

		curIndexClnUp = Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastTidx != curTidx)
		{
			processQueue(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx, Global::TIME_INDEX);;
		}

		if(curIndexClnUp != lastIndexClnUp) /* Every Min jobs */
		{
			pUdpSMInterface->sessionTimeOutClean(false);	// IP Cleanup
			lastIndexClnUp = curIndexClnUp;
		}

		executeDayEndActivity();

	} /* End Of (Main) While Loop */

	printf("  UDP SM [%02d] Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void udpSM::executeDayEndActivity()
{
	/* End of the Day Activity */
	if(Global::CURRENT_HOUR == Global::END_OF_DAY_CLEAN_HOUR && Global::CURRENT_MIN == Global::END_OF_DAY_CLEAN_MIN && Global::CURRENT_SEC == Global::END_OF_DAY_CLEAN_SEC)
	{
		for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
			for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; r++)
				for(uint16_t t = 0; t < 10; t++)
				{
					SmStore::udpBusy[instanceId][i][r][t] = false;
					SmStore::udpCnt[instanceId][i][r][t] = 0;
					SmStore::udpStore[instanceId][i][r][t].clear();
				}

		pUdpSMInterface->sessionTimeOutClean(true);
	}
}

void udpSM::processQueue(uint16_t t_index)
{
	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
		for(uint16_t k = 0; k < Global::ROUTER_PER_INTERFACE[i]; k++)
			processPackets(SmStore::udpBusy[instanceId][i][k][t_index], SmStore::udpCnt[instanceId][i][k][t_index],SmStore::udpStore[instanceId][i][k][t_index]);
}

void udpSM::processPackets(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, MPacket> &store)
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

void udpSM::callInterface(MPacket *msgObj)
{
	switch(msgObj->pType)
	{
		case PACKET_IPPROTO_UDP:
				Global::SM_UDP_PACKETS_PER_DAY[instanceId]++;
				pUdpSMInterface->packetEntry(msgObj);
				break;

		default:
				break;
	}
}
