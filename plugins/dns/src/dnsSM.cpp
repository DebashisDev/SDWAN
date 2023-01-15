/*
 * dnsSM.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "dnsSM.h"

dnsSM::dnsSM(uint16_t id)
{
	this->_name = "dnsSM";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->initStats 		= false;
	this->lastTidx			= 0;
	this->curTidx			= 0;
	this->curIndexClnUp		= 0;
	this->lastIndexClnUp	= 0;
	this->pDnsSMInterface	= new dnsSMInterface(id);
	this->pUdpSMInterface	= new udpSMInterface(id);
}

dnsSM::~dnsSM()
{
	delete (pDnsSMInterface);
}

bool dnsSM::isInitialized()
{ return initStats; }

void dnsSM::run()
{
	initStats = true;
	curIndexClnUp = lastIndexClnUp 	= Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::DNS_SESSION_MANAGER_RUNNING_STATUS[instanceId])
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
			pDnsSMInterface->sessionTimeOutClean();
			lastIndexClnUp = curIndexClnUp;
		}
	} /* End Of (Main) While Loop */

	printf("  Dns SM [%02d] Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void dnsSM::processQueue(uint16_t t_index)
{
	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
		for(uint16_t k = 0; k < Global::ROUTER_PER_INTERFACE[i]; k++)
			processPackets(SmStore::dnsBusy[instanceId][i][k][t_index], SmStore::dnsCnt[instanceId][i][k][t_index],SmStore::dnsStore[instanceId][i][k][t_index]);
}

void dnsSM::processPackets(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, MPacket> &store)
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

void dnsSM::callInterface(MPacket *msgObj)
{
	switch(msgObj->pType)
	{
		case PACKET_IPPROTO_DNS:
				Global::SM_DNS_PACKETS_PER_DAY[instanceId]++;
				pDnsSMInterface->DnsPacketEntry(msgObj);

				if(!Global::UDP_XDR_FOR_DNS)
					return;

				pUdpSMInterface->packetEntry(msgObj);
				break;

		default:
				break;
	}
}
