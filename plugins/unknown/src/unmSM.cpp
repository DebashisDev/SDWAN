/*
 * UnSessionManager.cpp
 *
 *  Created on: 15-Aug-2021
 *      Author: Debashis
 */

#include "unmSM.h"

unmSM::unmSM(uint16_t id)
{
	this->_name = "unmSM";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->unSMReadyState 	= false;

	this->lastIndex 		= 0;
	this->curIndex 			= 0;
	this->curIndexClnUp		= 0;
	this->lastIndexClnUp	= 0;
	this->unTcpSM			= new unmTcpInterface(this->instanceId);
	this->unUdpSM			= new unmUdpInterface(this->instanceId);
}

unmSM::~unmSM()
{
	delete(unTcpSM);
	delete(unUdpSM);
}

bool unmSM::isInitialized()
{ return unSMReadyState; }

void unmSM::run()
{
	curIndexClnUp = lastIndexClnUp 	= Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);
	unSMReadyState = true;

	while(Global::UNM_SESSION_MANAGER_RUNNING_STATUS[instanceId])
	{
		usleep(Global::SLEEP_TIME);		// 100ms

		curIndexClnUp = Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
		curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastIndex != curIndex)
		{
			ProcessQueue(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, Global::TIME_INDEX);
		}

		if(curIndexClnUp != lastIndexClnUp)
		{
			unTcpSM->tcpTimeOutClean();	// IP Cleanup
			unUdpSM->udpTimeOutClean();
			unUdpSM->dnsTimeOutClean();	// DNS Session Cleanup
			lastIndexClnUp = curIndexClnUp;
		}
	} /* End Of (Main) While Loop */

	printf("  UnMapped SM [%02d] Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void unmSM::ProcessQueue(uint16_t t_index)
{
	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
		for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; r++)
			processQueue_sm(SmStore::unBusy[instanceId][i][r][t_index], SmStore::unCnt[instanceId][i][r][t_index],SmStore::unStore[instanceId][i][r][t_index]);
}

void unmSM::processQueue_sm(bool &smBusy, uint32_t &smCnt, std::unordered_map<uint32_t, MPacket> &pkt)
{
	uint32_t recCnt = smCnt;

	if(recCnt > 0)
	{
		smBusy = true;

		for(uint32_t i = 0; i < recCnt; i++)
		{
			processPacket(&pkt[i]);
			pkt.erase(i);
		}
		pkt.clear();
		smCnt = 0;
		smBusy = false;
	}
}

void unmSM::processPacket(MPacket *pkt)
{
	if(pkt == NULL)
		return;

	Global::SM_UN_PACKETS_PER_DAY[instanceId] ++;

	switch(pkt->pType)
	{
		case PACKET_IPPROTO_DNS:
				unUdpSM->DNSPacketEntry(pkt);

				if(!Global::UDP_XDR_FOR_DNS)
					return;

				unUdpSM->UDPPacketEntry(pkt);
				break;

		case PACKET_IPPROTO_UDP:
				unUdpSM->UDPPacketEntry(pkt);
				break;

		case PACKET_IPPROTO_TCP:
				unTcpSM->TCPPacketEntry(pkt);
				break;
	}
}
