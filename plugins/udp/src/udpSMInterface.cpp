/*
 * udpSMInterface.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "udpSMInterface.h"

udpSMInterface::udpSMInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "udpSMInterface";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->cleanUpMapCnt 	= 0;

	initSessionPool();

	ipV4Key = 0;
	ipV6Key = "";
}

udpSMInterface::~udpSMInterface()
{ }

uint32_t udpSMInterface::getFreeIndex()
{
	freeBitPos++;
	if(freeBitPos >= freeBitPosMax) freeBitPos = 0;

	uint32_t arrId = freeBitPos / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = freeBitPos % UDP_SESSION_POOL_ARRAY_ELEMENTS;

	while(bitFlagsSession[arrId].test(bitId))
	{
		freeBitPos++;
		if(freeBitPos >= freeBitPosMax) freeBitPos = 0;
		arrId = freeBitPos / UDP_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = freeBitPos % UDP_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(freeBitPos >= freeBitPosMax)
	{ printf("[%d] getFreeIndexIp freeBitPosIp [%u] >= freeBitPosIpMax [%u]\n",instanceId, freeBitPos, freeBitPosMax); }
	bitFlagsSession[arrId].set(bitId);
	return freeBitPos;
}

void udpSMInterface::releaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UDP_SESSION_POOL_ARRAY_ELEMENTS;
	sessionPoolMap[arrId][bitId]->reset();
	sessionPoolMap[arrId][bitId]->poolIndex = idx;
	bitFlagsSession[arrId].reset(bitId);
}

void udpSMInterface::initSessionPool()
{
	freeBitPosMax = UDP_SESSION_POOL_ARRAY_ELEMENTS * UDP_SESSION_POOL_ARRAY_SIZE;

	printf("udpSMInterface [%02d]	Initializing [%u]  UDP Session Pool... ", instanceId, freeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UDP Session Pool...", instanceId, freeBitPosMax);

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_SIZE; i++)
	{
		bitFlagsSession[i].reset();
		for(uint16_t j = 0; j < UDP_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			sessionPoolMap[i][j] = new udpSession();
			sessionPoolMap[i][j]->poolIndex = (i*UDP_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%d] Initializing [%u] UDP Session Pool Completed.", instanceId, freeBitPosMax);
}

udpSession* udpSMInterface::getSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UDP_SESSION_POOL_ARRAY_ELEMENTS;
	return sessionPoolMap[arrId][bitId];
}

void udpSMInterface::getMapIndex(MPacket *msgObj, uint32_t &idx)
{
	ipV6Key = "";

	switch(msgObj->ipVer)
	{
		case IPVersion4:
		{
			ipV4Key = msgObj->ipv4FlowId;

			switch(msgObj->direction)
			{
				case UP:
					idx = msgObj->sIp % UDP_SESSION_POOL_ARRAY_ELEMENTS;
					break;

				case DOWN:
					idx = msgObj->dIp % UDP_SESSION_POOL_ARRAY_ELEMENTS;
					break;
			}
		}
		break;

		default:
				break;
	}
}

void udpSMInterface::packetEntry(MPacket *msgObj)
{
	if(msgObj == NULL)
		return;

	bool found = false;

	udpSession *pUdpSession = getSession(msgObj, &found, true);

	/* Couldn't Create Session */
	if(pUdpSession == NULL) return;

	timeStampArrivalPacket(pUdpSession, msgObj->frTimeEpochSec, msgObj->frTimeEpochNanoSec);

	/* Create New Session */
	if(!found)
	{
		initializeSession(pUdpSession, msgObj);
		updateSession(pUdpSession, msgObj);
	}
	else
	{ updateSession(pUdpSession, msgObj); }

	pUdpSession = NULL;
}

udpSession* udpSMInterface::getSession(MPacket *msgObj, bool *found, bool create)
{
	uint64_t sessionCnt;
	uint32_t mapIndex, poolIndex;
	udpSession *pUdpSession = NULL;

	sessionCnt = 0;
	mapIndex = poolIndex = 0;

	getMapIndex(msgObj, mapIndex);

	switch(msgObj->ipVer)
	{
		case IPVersion4:
		{
				std::map<uint64_t, uint32_t>::iterator it = v4SessionMap[mapIndex].find(msgObj->ipv4FlowId);

				if(it != v4SessionMap[mapIndex].end())
				{
					pUdpSession = getSessionFromPool(it->second);
					*found = true;
				}
				else
				{
					if(create)
					{
						for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
							sessionCnt += (v4SessionMap[i].size() + v6SessionMap[i].size());

						if(sessionCnt < freeBitPosMax)
						{
							poolIndex = getFreeIndex();
							pUdpSession = getSessionFromPool(poolIndex);
							pUdpSession->reset();

							pUdpSession->ipV4sessionKey = ipV4Key;
							pUdpSession->smInstanceId = this->instanceId;
							pUdpSession->mapIndex = mapIndex;
							pUdpSession->poolIndex = poolIndex;
							v4SessionMap[pUdpSession->mapIndex][pUdpSession->ipV4sessionKey] = poolIndex;
						}
					}
					*found = false;
				}
		}
		break;
	}
	return pUdpSession;
}

void udpSMInterface::initializeSession(udpSession *pUdpSession, MPacket *msgObj)
{
	pUdpSession->ipVer = msgObj->ipVer;
	pUdpSession->protocolType = PACKET_IPPROTO_UDP;
	pUdpSession->state = UD_UDP_DATA;
	pUdpSession->sliceCounter = 0;

	switch(msgObj->direction)
	{
		case UP:
				switch(msgObj->ipVer)
				{
					case IPVersion4:
						pUdpSession->sIpv4 = msgObj->sIp;
						pUdpSession->dIpv4 = msgObj->dIp;
						break;
				}
				pUdpSession->sPort = msgObj->sPort;
				pUdpSession->dPort = msgObj->dPort;
				break;

		case DOWN:
				switch(msgObj->ipVer)
				{
					case IPVersion4:
						pUdpSession->sIpv4 = msgObj->dIp;
						pUdpSession->dIpv4 = msgObj->sIp;
						break;
				}
				pUdpSession->sPort = msgObj->dPort;
				pUdpSession->dPort = msgObj->sPort;
				break;
	}

	pUdpSession->isUpDir = msgObj->direction;

	pUdpSession->startTimeEpochSec 		= pUdpSession->pckArivalTimeEpochSec;
	pUdpSession->startTimeEpochNanoSec 	= pUdpSession->pckLastTimeEpochNanoSec;
	pUdpSession->endTimeEpochNanoSec 	= pUdpSession->pckLastTimeEpochNanoSec;
}

void udpSMInterface::updateSession(udpSession *pUdpSession, MPacket *msgObj)
{
	uint64_t timeDiff = 0;

	pUdpSession->endTimeEpochNanoSec = pUdpSession->pckLastTimeEpochNanoSec;

	pUdpSession->frCount += 1;
	pUdpSession->frSize += msgObj->frSize;

	switch(msgObj->direction)
	{
		case UP:
				pUdpSession->upFrSize += msgObj->frSize;
				pUdpSession->upFrCount += 1;

				if(msgObj->pLoad > 0) {
					pUdpSession->pLoadPkt += 1;
					pUdpSession->pLoadSize +=  msgObj->pLoad;
					pUdpSession->upPLoadPkt += 1;
					pUdpSession->upPLoadSize += msgObj->pLoad;
				}
				break;

		case DOWN:
				pUdpSession->dnFrSize += msgObj->frSize;
				pUdpSession->dnFrCount += 1;

				if(msgObj->pLoad > 0) {
					pUdpSession->pLoadPkt += 1;
					pUdpSession->pLoadSize +=  msgObj->pLoad;
					pUdpSession->dnPLoadPkt += 1;
					pUdpSession->dnPLoadSize += msgObj->pLoad;
				}
				break;
	}

	/** Check the Data Slicing **/
	if(pUdpSession->frCount >= Global::SESSION_PKT_LIMIT)
	{
		pUdpSession->causeCode = SYSTEM_PKTLIMIT_UDP_DATA;

		flushSession(5, pUdpSession, false);
		pUdpSession->reuse();
	}
	else
	{
		if(pUdpSession->pckLastTimeEpochSec > pUdpSession->startTimeEpochSec){
			timeDiff = pUdpSession->pckLastTimeEpochSec - pUdpSession->startTimeEpochSec;

			if (timeDiff >= Global::SESSION_TIME_LIMIT) {
				pUdpSession->causeCode = SYSTEM_TIMEOUT_UDP_DATA;

				flushSession(9, pUdpSession, false);
				pUdpSession->reuse();
			}
		}
	}
}

void udpSMInterface::timeStampArrivalPacket(udpSession *pIpSession, uint64_t epochSec, uint64_t epochNanoSec)
{
	pIpSession->pckArivalTimeEpochSec 	= epochSec;
	pIpSession->pckLastTimeEpochSec 	= epochSec;
	pIpSession->pckLastTimeEpochNanoSec = epochNanoSec;
}

void udpSMInterface::flushSession(uint16_t flushOrgId, udpSession *pUdpSession, bool erase)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	pUdpSession->flushOrgId = flushOrgId;
	pUdpSession->flushTime = epochSecNow;
	pUdpSession->lastActivityTimeEpohSec = epochSecNow;

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	pUdpSession->sliceCounter += 1;
	storeSession(idx, pUdpSession);

	if(erase)
	{ eraseSession(pUdpSession); }
}

void udpSMInterface::storeSession(uint16_t tIdx, udpSession *pUdpSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_UDP_FLUSHER;

	if(flusherStore::udpCnt[flusherNo][instanceId][tIdx + 2] == 0)
	{
		flusherStore::udp[flusherNo][instanceId][tIdx][flusherStore::udpCnt[flusherNo][instanceId][tIdx]].copy(pUdpSession);
		flusherStore::udpCnt[flusherNo][instanceId][tIdx]++;
	}
	else
	{ eraseSession(pUdpSession); }
}

void udpSMInterface::sessionTimeOutClean(bool endOfDay)
{
	IPStats::smUdpV4SessionCnt[instanceId] = 0;
	IPStats::smUdpV6SessionCnt[instanceId] = 0;

	IPStats::smUdpV4SessionScan[instanceId] 	= 0;
	IPStats::smUdpV6SessionScan[instanceId] 	= 0;

	IPStats::smUdpV4SessionClean[instanceId] 	= 0;
	IPStats::smUdpV6SessionClean[instanceId] 	= 0;

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		IPStats::smUdpV4SessionCnt[instanceId] += v4SessionMap[i].size();
		IPStats::smUdpV6SessionCnt[instanceId] += v6SessionMap[i].size();
	}

	cleanUpMapCnt = 0;

	if(endOfDay)
	{
		TheLog_nc_v1(Log::Info, name()," End of the day Session Cleaning Started for Session Id [%02d]", instanceId);

		for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v4SessionMap[i].begin(), next_elem = elem; elem != v4SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smUdpV4SessionScan[instanceId]++;
			}
		}

		IPStats::smUdpV4SessionClean[instanceId] = cleanUpMapCnt;
		TheLog_nc_v2(Log::Info, name()," End of the day Ipv4 Session Cleaning Completed for Session Id [%02d] with Session [%u]", instanceId, cleanUpMapCnt);
		cleanUpMapCnt = 0;

		for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v6SessionMap[i].begin(), next_elem = elem; elem != v6SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smUdpV6SessionScan[instanceId]++;
			}
		}

		IPStats::smUdpV6SessionClean[instanceId] = cleanUpMapCnt;
		TheLog_nc_v2(Log::Info, name()," End of the day Ipv6 Session Cleaning Completed for Session Id [%02d] with Session [%u]", instanceId, cleanUpMapCnt);

		TheLog_nc_v2(Log::Info, name()," End of the day Session Cleaning Completed for Session Id [%02d] with Total Session [%u]", instanceId, (IPStats::smUdpV4SessionScan[instanceId] + IPStats::smUdpV6SessionScan[instanceId]));

		cleanUpMapCnt = 0;
	}
	else
	{
		for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v4SessionMap[i].begin(), next_elem = elem; elem != v4SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smUdpV4SessionScan[instanceId]++ ;
			}
		}
		IPStats::smUdpV4SessionClean[instanceId] = cleanUpMapCnt;

		cleanUpMapCnt = 0;

		for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v6SessionMap[i].begin(), next_elem = elem; elem != v6SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smUdpV6SessionScan[instanceId]++ ;
			}
		}
		IPStats::smUdpV6SessionClean[instanceId] = cleanUpMapCnt;
		cleanUpMapCnt = 0;
	}
}

void udpSMInterface::sessionTimedOutFlush(udpSession *pUdpSession, bool endOfDay)
{
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;

	if(endOfDay)
	{
		pUdpSession->causeCode = SYSTEM_CLEANUP_END_OF_DAY_IP_DATA;
		flushSession(7, pUdpSession, true);
		cleanUpMapCnt++;
	}
	else
	{
		if((curEpochSec - pUdpSession->pckLastTimeEpochSec) > Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC)
		{
			pUdpSession->causeCode = SYSTEM_CLEANUP_UDP_DATA;

			cleanUpMapCnt++;
			flushSession(7, pUdpSession, true);
		}
	}
}

void udpSMInterface::eraseSession(udpSession *pUdpSession)
{
	uint32_t idx;
	uint32_t poolIndex;

	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			uint64_t sKey4 = pUdpSession->ipV4sessionKey;
			idx = pUdpSession->mapIndex;
			poolIndex = pUdpSession->poolIndex;
			releaseIndex(poolIndex);
			v4SessionMap[idx].erase(sKey4);
		}
		break;
	}
}

