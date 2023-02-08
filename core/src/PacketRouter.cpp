/*
 * PacketRouter.cpp
 *
 *  Created on: Nov 22, 2016
 *      Author: Debashis
 */

#include <math.h>
#include "PacketRouter.h"

PacketRouter::PacketRouter(uint16_t intfid, uint16_t rid)
{
	this->_name = "PacketRouter";
	this->setLogLevel(Log::theLog().level());

	this->intfId 			= intfid;
	this->routerId 			= rid;
	this->initStatus 		= false;
	this->curMin 			= 0;
	this->prevMin 			= 0;
	this->curHour 			= 0;
	this->prevHour 			= 0;
	this->smId				= 0;
	this->maxPktLen 		= Global::MAX_PKT_LEN_PER_INTERFACE[this->intfId];

	this->bwData  			= new BWData(this->intfId, this->routerId);
	this->ethParser 		= new EthernetParser(this->intfId, this->routerId);
	this->msgObj 			= new MPacket();
}

PacketRouter::~PacketRouter()
{
	delete(this->bwData);
	delete(this->ethParser);
	delete(this->msgObj);
}

bool PacketRouter::isRouterInitialized()
{ return initStatus; }

void PacketRouter::run()
{
	uint16_t lastTidx, curTidx;
	struct tm *now_tm;

	curMin = prevMin 	= Global::CURRENT_MIN;
	curHour = prevHour 	= Global::CURRENT_HOUR;

	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	initStatus = true;

	while(Global::PKT_ROUTER_RUNNING_STATUS[intfId][routerId])
	{
		usleep(Global::SLEEP_TIME);

		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC,Global::TIME_INDEX);

		curMin = Global::CURRENT_MIN;

		if(prevMin != curMin)
		{
			bwData->setBWData(prevMin);
			prevMin = curMin;
		}

		while(lastTidx != curTidx)
		{
			processQueue(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx,Global::TIME_INDEX);
		}
	}

	printf("PacketRouter [%02d::%02d] Stopped.\n", this->intfId, this->routerId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void PacketRouter::processQueue(uint16_t tIdx)
{ processQueueDecode(PKTStore::busy[intfId][routerId][tIdx], PKTStore::cnt[intfId][routerId][tIdx], PKTStore::store[intfId][routerId][tIdx]); }

void PacketRouter::processQueueDecode(bool &busy, uint32_t &cnt, std::unordered_map<uint32_t, RawPkt*> &pktRepo)
{
	uint32_t recCnt = cnt;
	busy = true;

	if(recCnt > 0)
	{
		for(uint32_t i = 0; i < recCnt; i++)
		{
			decodePacket(pktRepo[i]);
			cnt--;
		}
		cnt = 0;
	}
	busy = false;
}

void PacketRouter::decodePacket(RawPkt *rawPkt)
{
	bool process = true;

	if(rawPkt->pkt != NULL)
	{
		msgObj->reset();
	    msgObj->frTimeEpochSec = rawPkt->tv_sec;
	    msgObj->frTimeEpochNanoSec = rawPkt->tv_nsec;
	    msgObj->frTimeEpochMilliSec = (rawPkt->tv_nsec / 1000000);
	    msgObj->frSize = rawPkt->len;

	    ethParser->parsePacket(rawPkt->pkt, msgObj);

	    bwData->updateBWData(curMin, msgObj);

	    if(msgObj->direction == 0) return;

	    switch(msgObj->ipVer)
	    {
			case IPVersion4:
			case IPVersion6:
					break;

			default:
					return;
					break;
	    }

		switch(msgObj->pType)
		{
			case PACKET_IPPROTO_TCP:
	    			Global::TCP_PACKETS_PER_DAY[intfId][routerId] ++;
	    			findSmForTcpPacket(msgObj);
					break;

			case PACKET_IPPROTO_UDP:
					Global::UDP_PACKETS_PER_DAY[intfId][routerId] ++;
					findSmForUdpPacket(msgObj);
					break;

			case PACKET_IPPROTO_DNS:
					Global::DNS_PACKETS_PER_DAY[intfId][routerId] ++;
					switch(msgObj->direction)
					{
						case UNMAPPED:
								smId = 0;
								break;
						case UP:
						case DOWN:
								smId = msgObj->transactionId % (Global::DNS_SESSION_MANAGER_INSTANCES);
								break;
					}
					findSmForDnsPacket(msgObj);
					break;

			default:
					break;
		}
	}	/* End of If */
}

/* TCP */
void PacketRouter::findSmForTcpPacket(MPacket* tcpPkt)
{
	smId = -1;

	if(tcpPkt->direction == 0)
		return;

	switch(tcpPkt->ipVer)
	{
		case IPVersion4:
				switch(tcpPkt->direction)
				{
					case UNMAPPED:
						smId = tcpPkt->ipv4FlowId % Global::UNM_SESSION_MANAGER_INSTANCES;
						break;

					default:
						smId = tcpPkt->ipv4FlowId % Global::TCP_SESSION_MANAGER_INSTANCES;
						break;
				}

				pushTcpPacketToSm(smId, tcpPkt);
				break;

		default:
				break;
	}
}

void PacketRouter::pushTcpPacketToSm(int16_t smid, MPacket *msgObj)
{
	if(smid == -1)
		return;

	uint16_t idx = PKT_WRITE_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	switch(msgObj->direction)
	{
		case UNMAPPED:
			copyMsgObj(idx, SmStore::unBusy[smid][intfId][routerId][idx], SmStore::unCnt[smid][intfId][routerId][idx], SmStore::unStore[smid][intfId][routerId][idx], msgObj);
			break;

		default:
			copyMsgObj(idx, SmStore::tcpBusy[smid][intfId][routerId][idx], SmStore::tcpCnt[smid][intfId][routerId][idx], SmStore::tcpStore[smid][intfId][routerId][idx], msgObj);
			break;
	}
}

/* UDP */
void PacketRouter::findSmForUdpPacket(MPacket* udpPkt)
{
	smId = -1;

	if(udpPkt->direction == 0)
		return;

	switch(udpPkt->ipVer)
	{
		case IPVersion4:
				switch(udpPkt->direction)
				{
					case UNMAPPED:
						smId = udpPkt->ipv4FlowId % Global::UNM_SESSION_MANAGER_INSTANCES;
						break;

					default:
						smId = udpPkt->ipv4FlowId % Global::UDP_SESSION_MANAGER_INSTANCES;
						break;
				}

				pushUdpPacketToSm(smId, udpPkt);
				break;

		default:
				break;
	}
}

void PacketRouter::pushUdpPacketToSm(int16_t smid, MPacket *msgObj)
{
	if(smid == -1)
		return;

	uint16_t idx = PKT_WRITE_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	switch(msgObj->direction)
	{
		case UNMAPPED:
			copyMsgObj(idx, SmStore::unBusy[smid][intfId][routerId][idx], SmStore::unCnt[smid][intfId][routerId][idx], SmStore::unStore[smid][intfId][routerId][idx], msgObj);
			break;

		default:
			copyMsgObj(idx, SmStore::udpBusy[smid][intfId][routerId][idx], SmStore::udpCnt[smid][intfId][routerId][idx], SmStore::udpStore[smid][intfId][routerId][idx], msgObj);
			break;
	}
}

/* DNS */
void PacketRouter::findSmForDnsPacket(MPacket* dnsPkt)
{
	smId = -1;

	if(dnsPkt->direction == 0)
		return;

	switch(dnsPkt->ipVer)
	{
		case IPVersion4:
				switch(dnsPkt->direction)
				{
					case UNMAPPED:
						smId = dnsPkt->ipv4FlowId % Global::UNM_SESSION_MANAGER_INSTANCES;
						break;

					default:
						smId = dnsPkt->ipv4FlowId % Global::DNS_SESSION_MANAGER_INSTANCES;
						break;
				}

				pushDnsPacketToSm(smId, dnsPkt);
				break;

		default:
				break;
	}
}

void PacketRouter::pushDnsPacketToSm(int16_t smid, MPacket *msgObj)
{
	if(smid == -1)
		return;

	uint16_t idx = PKT_WRITE_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	switch(msgObj->direction)
	{
		case UNMAPPED:
			copyMsgObj(idx, SmStore::unBusy[smid][intfId][routerId][idx], SmStore::unCnt[smid][intfId][routerId][idx], SmStore::unStore[smid][intfId][routerId][idx], msgObj);
			break;

		default:
			copyMsgObj(idx, SmStore::dnsBusy[smid][intfId][routerId][idx], SmStore::dnsCnt[smid][intfId][routerId][idx], SmStore::dnsStore[smid][intfId][routerId][idx], msgObj);
			break;
	}
}


void PacketRouter::copyMsgObj(uint16_t idx, bool &busy, uint32_t &counter, std::unordered_map<uint32_t, MPacket> &smStore, MPacket *msgObj)
{
	if(busy) return;

	smStore[counter].copy(msgObj);
	counter++;
}

bool PacketRouter::IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask)
{
    uint32_t net_lower = (network & mask);
    uint32_t net_upper = (net_lower | (~mask));

    if(ip >= net_lower && ip <= net_upper)
        return true;
    return false;
}
