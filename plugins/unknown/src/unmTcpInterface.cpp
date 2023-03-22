/*
 * UnTcpInetrface.cpp
 *
 *  Created on: 16-Aug-2021
 *      Author: singh
 */

#include "unmTcpInterface.h"

unmTcpInterface::unmTcpInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "unmTcpInterface";
	this->setLogLevel(Log::theLog().level());
	this->instanceId = id;
	this->timeindex = 0;
	tcpInitializeSessionPool();
	cleanUpCnt = 0;

	ipV4Key = 0;
	ipV6Key = "";
}

unmTcpInterface::~unmTcpInterface()
{ }

uint32_t unmTcpInterface::getMapIndexAndSessionKey(MPacket *tcpMsg)
{
    uint32_t mapIndex = 0;

    switch(tcpMsg->ipVer)
    {
    	case IPVersion4:
    	{
			ipV4Key = tcpMsg->ipv4FlowId;
			mapIndex = tcpMsg->sIp % UNM_SESSION_POOL_ARRAY_ELEMENTS;
    	}
    	break;

		case IPVersion6:
		{
			ipV6Key = std::to_string(PACKET_IPPROTO_TCP) + (tcpMsg->sIpv6) + std::to_string(tcpMsg->sPort) + (tcpMsg->dIpv6) + std::to_string(tcpMsg->dPort);
			mapIndex = tcpMsg->sPort % UNM_SESSION_POOL_ARRAY_ELEMENTS;
		}
		break;

    	default:
    			break;
	}
	return mapIndex;
}

uint32_t unmTcpInterface::tcpGetFreeIndex()
{
	tcpFreeBitPos++;
	if(tcpFreeBitPos >= tcpFreeBitPosMax) tcpFreeBitPos = 0;
	int arrId = tcpFreeBitPos / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	int bitId = tcpFreeBitPos % UNM_SESSION_POOL_ARRAY_ELEMENTS;

	while(tcpBitFlagsSession[arrId].test(bitId)){
		tcpFreeBitPos++;
		if(tcpFreeBitPos >= tcpFreeBitPosMax) tcpFreeBitPos = 0;
		arrId = tcpFreeBitPos / UNM_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = tcpFreeBitPos % UNM_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(tcpFreeBitPos >= tcpFreeBitPosMax){
		printf("[%d] getFreeIndexIp freeBitPosIp [%u] >= freeBitPosIpMax [%u]\n",instanceId, tcpFreeBitPos, tcpFreeBitPosMax);
	}
	tcpBitFlagsSession[arrId].set(bitId);
	return tcpFreeBitPos;
}

void unmTcpInterface::tcpReleaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UNM_SESSION_POOL_ARRAY_ELEMENTS;

	tcpSessionPoolMap[arrId][bitId]->reset();
	tcpSessionPoolMap[arrId][bitId]->poolIndex = idx;
	tcpBitFlagsSession[arrId].reset(bitId);
}

void unmTcpInterface::tcpInitializeSessionPool()
{
	tcpFreeBitPosMax = UNM_SESSION_POOL_ARRAY_ELEMENTS * UNM_SESSION_POOL_ARRAY_SIZE;

	printf("IPSMInterface [%02d]	Initializing [%u] UNM TCP Session Pool... ", instanceId, tcpFreeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UNM TCP Session Pool...", instanceId, tcpFreeBitPosMax);
	for(int i=0; i<UNM_SESSION_POOL_ARRAY_SIZE; i++)
	{
		tcpBitFlagsSession[i].reset();
		for(int j=0; j<UNM_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			tcpSessionPoolMap[i][j] = new tcpSession();
			tcpSessionPoolMap[i][j]->poolIndex = (i*UNM_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UNM TCP Session Pool Completed.", instanceId, tcpFreeBitPosMax);
}

tcpSession* unmTcpInterface::tcpGetSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UNM_SESSION_POOL_ARRAY_ELEMENTS;
	return tcpSessionPoolMap[arrId][bitId];
}

tcpSession* unmTcpInterface::tcpGetSession(MPacket *tcpMsg, bool *found, bool create)
{
	uint32_t sessionCnt = 0;
	tcpSession *pTcpSession = NULL;
	uint32_t mapIndex, poolIndex;

	mapIndex = getMapIndexAndSessionKey(tcpMsg);

	switch(tcpMsg->ipVer)
	{
		case IPVersion4:
		{
			std::map<uint64_t, uint32_t>::iterator it = tcpV4SessionMap[mapIndex].find(ipV4Key);

			if(it != tcpV4SessionMap[mapIndex].end())
			{
				pTcpSession = tcpGetSessionFromPool(it->second);
				*found = true;
			}
			else
			{
				if(create)
				{
					for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
						sessionCnt += (tcpV4SessionMap[i].size());

					if(sessionCnt < tcpFreeBitPosMax)
					{
						poolIndex = tcpGetFreeIndex();
						pTcpSession = tcpGetSessionFromPool(poolIndex);
						pTcpSession->reset();

						pTcpSession->ipV4sessionKey = ipV4Key;
						pTcpSession->mapIndex = mapIndex;
						pTcpSession->poolIndex = poolIndex;
						tcpV4SessionMap[pTcpSession->mapIndex][pTcpSession->ipV4sessionKey] = poolIndex;
					}
				}
				*found = false;
			}
		}
		break;
	}
	return pTcpSession;
}

void unmTcpInterface::TCPPacketEntry(MPacket *tcpMsg)
{
	bool found = false;

	tcpSession *pTcpSession;
	pTcpSession = tcpGetSession(tcpMsg, &found, true);


	/* Couldn't Create Session */
	if(pTcpSession == NULL) return;

	timeStampArrivalPacket(pTcpSession, tcpMsg->frTimeEpochSec, tcpMsg->frTimeEpochNanoSec);

	/* Create New Session */
	if(!found)
	{
		tcpInitializeSession(pTcpSession, tcpMsg);	/* Initialize TCP Packet */
		tcpUpdateSession(pTcpSession, tcpMsg);			/* Update TCP Packet */
	}
	else
	{
		tcpUpdateSession(pTcpSession, tcpMsg);
	}

	if(tcpMsg->tcpFlags == FIN_RCV)
		tcpFlushSession(3, pTcpSession, true);

	pTcpSession = NULL;
}

void unmTcpInterface::tcpInitializeSession(tcpSession *pTcpSession, MPacket *tcpMsg)
{
	pTcpSession->ipVer = tcpMsg->ipVer;
	pTcpSession->protocolType = PACKET_IPPROTO_TCP;

	switch(tcpMsg->ipVer)
	{
		case IPVersion4:
					pTcpSession->sIpv4 = tcpMsg->sIp;
					pTcpSession->dIpv4 = tcpMsg->dIp;
					break;
	}

	pTcpSession->sPort = tcpMsg->sPort;
	pTcpSession->dPort = tcpMsg->dPort;

	pTcpSession->sliceCounter = 0;

	pTcpSession->startTimeEpochSec = pTcpSession->pckArivalTimeEpochSec;
	pTcpSession->startTimeEpochNanoSec = pTcpSession->pckLastTimeEpochNanoSec;
	pTcpSession->endTimeEpochNanoSec = pTcpSession->pckLastTimeEpochNanoSec;
}

void unmTcpInterface::timeStampArrivalPacket(tcpSession *pTcpSession, uint64_t epochSec, uint64_t epochNanoSec)
{
	pTcpSession->pckArivalTimeEpochSec 	= epochSec;
	pTcpSession->pckLastTimeEpochSec 	= epochSec;
	pTcpSession->pckLastTimeEpochNanoSec = epochNanoSec;
}

void unmTcpInterface::tcpUpdateSession(tcpSession *pTcpSession, MPacket *tcpMsg)
{
	uint64_t timeDiff = 0;

	pTcpSession->endTimeEpochNanoSec = pTcpSession->pckLastTimeEpochNanoSec;

	pTcpSession->frCount += 1;
	pTcpSession->frSize += tcpMsg->frSize;

		if(tcpMsg->pLoad > 0)
		{
			pTcpSession->pLoadPkt += 1;
			pTcpSession->pLoadSize +=  tcpMsg->pLoad;
		}

	/*
	 * Don't flush the TCP Session which don't have connection
	 */
	if((pTcpSession->frCount >= Global::SESSION_PKT_LIMIT))
	{
		tcpFlushSession(4, pTcpSession, false);
		pTcpSession->reuse();
	}
	else
	{
		if(pTcpSession->pckLastTimeEpochSec > pTcpSession->startTimeEpochSec)
		{
			timeDiff = pTcpSession->pckLastTimeEpochSec - pTcpSession->startTimeEpochSec;

			if(timeDiff >= Global::SESSION_TIME_LIMIT)
			{
				tcpFlushSession(4, pTcpSession, false);
				pTcpSession->reuse();
			}
		}
	}
}

void unmTcpInterface::tcpFlushSession(uint16_t flushOrgId, tcpSession *pTcpSession, bool erase)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	pTcpSession->flushOrgId = flushOrgId;
	pTcpSession->flushTime = epochSecNow;
	pTcpSession->lastActivityTimeEpohSec = epochSecNow;

	timeindex = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	pTcpSession->sliceCounter += 1;
	tcpStoreSession(timeindex, pTcpSession);

	if(erase)
		tcpEraseSession(pTcpSession);
}

void unmTcpInterface::tcpStoreSession(uint16_t timeIndex, tcpSession *pTcpSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_UNM_FLUSHER;

	if(flusherStore::utcpCnt[flusherNo][instanceId][timeIndex + 2] == 0)
	{
		flusherStore::utcp[flusherNo][instanceId][timeIndex][flusherStore::utcpCnt[flusherNo][instanceId][timeIndex]].copy(pTcpSession);
		flusherStore::utcpCnt[flusherNo][instanceId][timeIndex]++;
	}
	else
	{ tcpEraseSession(pTcpSession); }
}

void unmTcpInterface::tcpTimeOutClean()
{
	cleanUpCnt = 0;

	IPStats::smUnTcpSessionCnt[instanceId] 		= 0;
	IPStats::smUnTcpSessionScan[instanceId] 	= 0;
	IPStats::smUnTcpSessionClean[instanceId] 	= 0;


	for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::smUnTcpSessionCnt[instanceId] += (tcpV4SessionMap[i].size());


	for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		for(auto elem = tcpV4SessionMap[i].begin(), next_elem = elem; elem != tcpV4SessionMap[i].end(); elem = next_elem)
		{
			++next_elem;
			tcpCleanSession(tcpGetSessionFromPool(elem->second));
			IPStats::smUnTcpSessionScan[instanceId]++ ;
		}
	}
	cleanUpCnt = 0;
}

void unmTcpInterface::tcpCleanSession(tcpSession *pTcpSession)
{
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;

	if((curEpochSec - pTcpSession->pckLastTimeEpochSec) > Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC)
	{
		pTcpSession->causeCode = SYSTEM_CLEANUP_TCP_DATA;
		IPStats::smUnTcpSessionClean[instanceId]++;
		cleanUpCnt++;
		tcpFlushSession(7, pTcpSession, true);
	}
}

void unmTcpInterface::tcpEraseSession(tcpSession *pTcpSession)
{
	uint32_t index, poolIndex;

	switch(pTcpSession->ipVer)
	{
		case IPVersion4:
		{
			uint64_t sKey4 = pTcpSession->ipV4sessionKey;
			index = pTcpSession->mapIndex;
			poolIndex = pTcpSession->poolIndex;
			tcpReleaseIndex(poolIndex);
			tcpV4SessionMap[index].erase(sKey4);
		}
		break;
	}
}
