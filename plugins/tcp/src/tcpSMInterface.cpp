/*
 * IPSMInterface.cpp
 *
 *  Created on: 20-Jul-2016
 *      Author: Debashis
 */

#include "tcpSMInterface.h"

#include "sys/time.h"
#include <locale.h>

tcpSMInterface::tcpSMInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "tcpSMInterface";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->cleanUpCnt 	= 0;

	initSessionPool();
}

tcpSMInterface::~tcpSMInterface()
{ }

void tcpSMInterface::getMapIndex(MPacket *msgObj, uint32_t &idx)
{
	ipV6Key = "";
	ipV4Key = 0;

	switch(msgObj->ipVer)
	{
		case IPVersion4:
		{
			switch(msgObj->direction)
			{
				case UP:
						ipV4Key = msgObj->ipv4FlowId;
						idx = msgObj->sIp % TCP_SESSION_POOL_ARRAY_ELEMENTS;
						break;

				case DOWN:
						ipV4Key = msgObj->ipv4FlowId;
						idx = msgObj->dIp % TCP_SESSION_POOL_ARRAY_ELEMENTS;
						break;
			}
			break;
		}
		break;

//		case IPVersion6:
//				switch(msgObj->pType)
//				{
//					case PACKET_IPPROTO_TCP:
//					case PACKET_IPPROTO_UDP:
//							switch(msgObj->direction)
//							{
//								case UP:
//										ipV6Key = std::to_string(msgObj->pType) +
//												  (msgObj->sIpv6) + std::to_string(msgObj->sPort) +
//												  (msgObj->dIpv6) + std::to_string(msgObj->dPort);
//										idx = msgObj->sPort % TCP_SESSION_POOL_ARRAY_ELEMENTS;
//										break;
//
//								case DOWN:
//										ipV6Key = std::to_string(msgObj->pType) +
//											  (msgObj->dIpv6) + std::to_string(msgObj->dPort) +
//											  (msgObj->sIpv6) + std::to_string(msgObj->sPort);
//										idx = msgObj->dPort % TCP_SESSION_POOL_ARRAY_ELEMENTS;
//										break;
//							}
//							break;
//					default:
//							break;
//				}
//				break;

		default:
				break;
	}
}

/* IP Functions */

uint32_t tcpSMInterface::getFreeIndex()
{
	freeBitPos++;
	if(freeBitPos >= freeBitPosMax) freeBitPos = 0;

	uint32_t arrId = freeBitPos / TCP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = freeBitPos % TCP_SESSION_POOL_ARRAY_ELEMENTS;

	while(bitFlagsSession[arrId].test(bitId))
	{
		freeBitPos++;
		if(freeBitPos >= freeBitPosMax) freeBitPos = 0;
		arrId = freeBitPos / TCP_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = freeBitPos % TCP_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(freeBitPos >= freeBitPosMax)
	{ printf("[%d] getFreeIndexIp freeBitPosIp [%u] >= freeBitPosIpMax [%u]\n",instanceId, freeBitPos, freeBitPosMax); }
	bitFlagsSession[arrId].set(bitId);
	return freeBitPos;
}

void tcpSMInterface::releaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / TCP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % TCP_SESSION_POOL_ARRAY_ELEMENTS;
	sessionPoolMap[arrId][bitId]->reset();
	sessionPoolMap[arrId][bitId]->poolIndex = idx;
	bitFlagsSession[arrId].reset(bitId);
}

void tcpSMInterface::initSessionPool()
{
	freeBitPosMax = TCP_SESSION_POOL_ARRAY_ELEMENTS * TCP_SESSION_POOL_ARRAY_SIZE;

	printf("tcpSMInterface [%02d]	Initializing [%u]  IP Session Pool... ", instanceId, freeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] IP Session Pool...", instanceId, freeBitPosMax);

	for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_SIZE; i++)
	{
		bitFlagsSession[i].reset();
		for(uint16_t j = 0; j < TCP_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			sessionPoolMap[i][j] = new tcpSession();
			sessionPoolMap[i][j]->poolIndex = (i*TCP_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%d] Initializing [%u] IP Session Pool Completed.", instanceId, freeBitPosMax);
}

tcpSession* tcpSMInterface::getSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / TCP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % TCP_SESSION_POOL_ARRAY_ELEMENTS;
	return sessionPoolMap[arrId][bitId];
}

tcpSession* tcpSMInterface::getSession(MPacket *msgObj, bool *found, bool create)
{
	uint64_t sessionCnt;
	uint32_t mapIndex, poolIndex;
	tcpSession *pTcpSession = NULL;

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
					pTcpSession = getSessionFromPool(it->second);
					*found = true;
				}
				else
				{
					if(create)
					{
						for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
							sessionCnt += (v4SessionMap[i].size() + v6SessionMap[i].size());

						if(sessionCnt < freeBitPosMax)
						{
							poolIndex = getFreeIndex();
							pTcpSession = getSessionFromPool(poolIndex);
							pTcpSession->reset();

							pTcpSession->ipV4sessionKey = ipV4Key;
							pTcpSession->mapIndex = mapIndex;
							pTcpSession->poolIndex = poolIndex;
							v4SessionMap[pTcpSession->mapIndex][pTcpSession->ipV4sessionKey] = poolIndex;
						}
					}
					*found = false;
				}
		}
		break;

//		case IPVersion6:
//		{
//				std::map<string, uint32_t>::iterator it1 = v6SessionMap[mapIndex].find(ipV6Key);
//
//				if(it1 != v6SessionMap[mapIndex].end())
//				{
//					pTcpSession = getSessionFromPool(it1->second);
//					*found = true;
//				}
//				else
//				{
//					if(create)
//					{
//						for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
//							sessionCnt += (v4SessionMap[i].size() + v6SessionMap[i].size());
//
//						if(sessionCnt < freeBitPosMax)
//						{
//							poolIndex = getFreeIndex();
//							pTcpSession = getSessionFromPool(poolIndex);
//							pTcpSession->reset();
//
//							pTcpSession->ipV6sessionKey = ipV6Key;
//							pTcpSession->mapIndex = mapIndex;
//							pTcpSession->poolIndex = poolIndex;
//							v6SessionMap[pTcpSession->mapIndex][pTcpSession->ipV6sessionKey] = poolIndex;
//						}
//					}
//					*found = false;
//				}
//		}
//		break;
	}
	return pTcpSession;
}

void tcpSMInterface::packetEntry(MPacket *msgObj)
{
	if(msgObj == NULL)
		return;

	bool found = false;
	tcpSession *pTcpSession;

	switch(msgObj->tcpFlags)
	{
		case  SYN_RCV:
		case SYN_ACK_RCV:
		case ACK_RCV:
		case DATA_RCV:
				pTcpSession = getSession(msgObj, &found, true);
				/* Couldn't Create Session */
				if(pTcpSession == NULL) return;

				timeStampArrivalPacket(pTcpSession, msgObj->frTimeEpochSec, msgObj->frTimeEpochNanoSec);

				/* Create New Session */
				if(!found)
				{
					initializeSession(pTcpSession, msgObj);	/* Initialize TCP Packet */
					updateTcpSession(pTcpSession, msgObj);			/* Update TCP Packet */
					return;
				}
				else
				{
					updateTcpSession(pTcpSession, msgObj);
				}

			break;

		case FIN_RCV:
				pTcpSession = getSession(msgObj, &found, false);

				/* Couldn't Create Session */
				if(pTcpSession == NULL) return;
				else
				{
					timeStampArrivalPacket(pTcpSession, msgObj->frTimeEpochSec, msgObj->frTimeEpochNanoSec);
					updateTcpSession(pTcpSession, msgObj);
					flushSession(3, pTcpSession, true);
				}
				break;

		default:
			break;
	}
	pTcpSession = NULL;  // Need to Check (TBD)
} // End Of updateTCPSession Function

void tcpSMInterface::initializeSession(tcpSession *pIpSession, MPacket *msgObj)
{
	pIpSession->ipVer 			= msgObj->ipVer;
	pIpSession->protocolType 	= PACKET_IPPROTO_TCP;

	switch(msgObj->ipVer)
	{
		case IPVersion4:
				switch(msgObj->direction)
				{
					case UP:
						pIpSession->sIpv4 = msgObj->sIp;
						pIpSession->dIpv4 = msgObj->dIp;
						pIpSession->sPort = msgObj->sPort;
						pIpSession->dPort = msgObj->dPort;
						strcpy(pIpSession->sMac, msgObj->sMac);
						break;

					case DOWN:
						pIpSession->sIpv4 = msgObj->dIp;
						pIpSession->dIpv4 = msgObj->sIp;
						pIpSession->sPort = msgObj->dPort;
						pIpSession->dPort = msgObj->sPort;
						strcpy(pIpSession->sMac, msgObj->dMac);
						break;
				}
				break;

//		case IPVersion6:
//				switch(msgObj->direction)
//				{
//				case UP:
//						strcpy(pIpSession->sIpv6, msgObj->sIpv6);
//						strcpy(pIpSession->dIpv6, msgObj->dIpv6);
//						pIpSession->sPort = msgObj->sPort;
//						pIpSession->dPort = msgObj->dPort;
//
//					break;
//
//				case DOWN:
//						strcpy(pIpSession->sIpv6, msgObj->dIpv6);
//						strcpy(pIpSession->dIpv6, msgObj->sIpv6);
//						pIpSession->sPort = msgObj->dPort;
//						pIpSession->dPort = msgObj->sPort;
//
//					break;
//				}
//				break;
	}
	pIpSession->isUpDir = msgObj->direction;
	pIpSession->sliceCounter = 0;

	pIpSession->startTimeEpochSec = pIpSession->pckArivalTimeEpochSec;
	pIpSession->startTimeEpochNanoSec = pIpSession->pckLastTimeEpochNanoSec;

	pIpSession->endTimeEpochNanoSec = pIpSession->pckLastTimeEpochNanoSec;
}


void tcpSMInterface::timeStampArrivalPacket(tcpSession *pIpSession, uint64_t epochSec, uint64_t epochNanoSec)
{
	pIpSession->pckArivalTimeEpochSec 	= epochSec;
	pIpSession->pckLastTimeEpochSec 	= epochSec;
	pIpSession->pckLastTimeEpochNanoSec = epochNanoSec;
}

void tcpSMInterface::updateTcpSession(tcpSession *pIpSession, MPacket *msgObj)
{
	uint64_t timeDiff = 0;

	pIpSession->endTimeEpochNanoSec = pIpSession->pckLastTimeEpochNanoSec;

	pIpSession->frCount += 1;
	pIpSession->frSize += msgObj->frSize;

	pIpSession->pLoadPkt += 1;
	pIpSession->pLoadSize +=  msgObj->pLoad;

	switch(msgObj->direction)
	{
		case UP:
			pIpSession->upFrSize += msgObj->frSize;
			pIpSession->upFrCount += 1;

			if(msgObj->pLoad > 0)
			{
				pIpSession->upPLoadPkt += 1;
				pIpSession->upPLoadSize += msgObj->pLoad;
			}
			break;

		case DOWN:
			pIpSession->dnFrSize += msgObj->frSize;
			pIpSession->dnFrCount += 1;

			if(msgObj->pLoad > 0)
			{
				pIpSession->dnPLoadPkt += 1;
				pIpSession->dnPLoadSize += msgObj->pLoad;
			}
			break;
	}

	if(msgObj->tcpFlags != FIN_RCV )
	{
		/*
		 * Don't flush the TCP Session which don't have connection
		 */
		if((pIpSession->frCount >= Global::SESSION_PKT_LIMIT))
		{
			pIpSession->causeCode = SYSTEM_PKTLIMIT_TCP_CONN_DATA;
			flushSession(4, pIpSession, false);
			pIpSession->reuse();
		}
		else
		{
			if(pIpSession->pckLastTimeEpochSec > pIpSession->startTimeEpochSec)
			{
				timeDiff = pIpSession->pckLastTimeEpochSec - pIpSession->startTimeEpochSec;

				if(timeDiff >= Global::SESSION_TIME_LIMIT)
				{
					pIpSession->causeCode = SYSTEM_TIMEOUT_TCP_CONN_DATA;
					flushSession(8, pIpSession, false);
					pIpSession->reuse();
				}
			}
		}
	}
}

void tcpSMInterface::flushSession(uint16_t flushOrgId, tcpSession *pIpSession, bool erase)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	pIpSession->flushOrgId = flushOrgId;
	pIpSession->flushTime = epochSecNow;
	pIpSession->lastActivityTimeEpohSec = epochSecNow;

	tIdx = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	if(pIpSession->protocolType == PACKET_IPPROTO_TCP)
	{
		if(pIpSession->frCount < 5 && flushOrgId == 7)
		{
			eraseSession(pIpSession);
			return;
		}
	}

	pIpSession->sliceCounter += 1;
	storeSession(tIdx, pIpSession);

	if(erase) {
		eraseSession(pIpSession);
	}
}

void tcpSMInterface::storeSession(uint16_t timeIndex, tcpSession *pTcpSession)
{
	flusherId = instanceId % Global::NO_OF_TCP_FLUSHER;

	if(flusherStore::tcpCnt[flusherId][instanceId][timeIndex + 2] == 0)
	{
		flusherStore::tcp[flusherId][instanceId][timeIndex][flusherStore::tcpCnt[flusherId][instanceId][timeIndex]].copy(pTcpSession);
		flusherStore::tcpCnt[flusherId][instanceId][timeIndex]++;
	}
	else
	{ eraseSession(pTcpSession); }
}

void tcpSMInterface::sessionTimeOutClean(bool endOfDay)
{
	cleanUpCnt = 0;

	IPStats::smTcpV4SessionCnt[instanceId] = 0;
	IPStats::smTcpV6SessionCnt[instanceId] = 0;

	IPStats::smTcpV4SessionScan[instanceId] 	= 0;
	IPStats::smTcpV6SessionScan[instanceId] 	= 0;

	IPStats::smTcpV4SessionClean[instanceId] 	= 0;
	IPStats::smTcpV6SessionClean[instanceId] 	= 0;

	for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		IPStats::smTcpV4SessionCnt[instanceId] += v4SessionMap[i].size();
		IPStats::smTcpV6SessionCnt[instanceId] += v6SessionMap[i].size();
	}

	if(endOfDay)
	{
		TheLog_nc_v1(Log::Info, name()," End of the day Session Cleaning Started for Session Id [%02d]", instanceId);

		for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v4SessionMap[i].begin(), next_elem = elem; elem != v4SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smTcpV4SessionScan[instanceId] ++;
			}
		}

		IPStats::smTcpV4SessionClean[instanceId] = cleanUpCnt;
		TheLog_nc_v2(Log::Info, name()," End of the day Ipv4 Session Cleaning Completed for Session Id [%02d] with Session [%u]", instanceId, cleanUpCnt);
		cleanUpCnt = 0;

		for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v6SessionMap[i].begin(), next_elem = elem; elem != v6SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smTcpV6SessionScan[instanceId] ++;
			}
		}

		IPStats::smTcpV6SessionClean[instanceId] = cleanUpCnt;
		TheLog_nc_v2(Log::Info, name()," End of the day Ipv6 Session Cleaning Completed for Session Id [%02d] with Session [%u]", instanceId, cleanUpCnt);

		TheLog_nc_v2(Log::Info, name()," End of the day Session Cleaning Completed for Session Id [%02d] with Total Session [%u]", instanceId, (IPStats::smTcpV4SessionScan[instanceId] + IPStats::smTcpV6SessionScan[instanceId]));

		cleanUpCnt = 0;
	}
	else
	{
		for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v4SessionMap[i].begin(), next_elem = elem; elem != v4SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smTcpV4SessionScan[instanceId]++ ;
			}
		}
		IPStats::smTcpV4SessionClean[instanceId] = cleanUpCnt;

		cleanUpCnt = 0;

		for(uint16_t i = 0; i < TCP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		{
			for(auto elem = v6SessionMap[i].begin(), next_elem = elem; elem != v6SessionMap[i].end(); elem = next_elem)
			{
				++next_elem;
				sessionTimedOutFlush(getSessionFromPool(elem->second), endOfDay);
				IPStats::smTcpV6SessionScan[instanceId]++ ;
			}
		}
		IPStats::smTcpV6SessionClean[instanceId] = cleanUpCnt;
		cleanUpCnt = 0;
	}
}

void tcpSMInterface::sessionTimedOutFlush(tcpSession *pIpSession, bool endOfDay)
{
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;

	if(endOfDay)
	{
		pIpSession->causeCode = SYSTEM_CLEANUP_END_OF_DAY_IP_DATA;
		flushSession(7, pIpSession, true);
		cleanUpCnt++;
	}
	else
	{
		if((curEpochSec - pIpSession->pckLastTimeEpochSec) > Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC)
		{
			pIpSession->causeCode = SYSTEM_CLEANUP_TCP_DATA;

			cleanUpCnt++;
			flushSession(7, pIpSession, true);
		}
	}
}

void tcpSMInterface::eraseSession(tcpSession *pIpSession)
{
	uint32_t idx;
	uint32_t poolIndex;

	switch(pIpSession->ipVer)
	{
		case IPVersion4:
		{
			uint64_t sKey4 = pIpSession->ipV4sessionKey;
			idx = pIpSession->mapIndex;
			poolIndex = pIpSession->poolIndex;
			releaseIndex(poolIndex);
			v4SessionMap[idx].erase(sKey4);
		}
		break;

//		case IPVersion6:
//		{
//			string sKey6 = pIpSession->ipV6sessionKey;
//			idx = pIpSession->mapIndex;
//			poolIndex = pIpSession->poolIndex;
//			releaseIndex(poolIndex);
//			v6SessionMap[idx].erase(sKey6);
//		}
//		break;
	}
}
