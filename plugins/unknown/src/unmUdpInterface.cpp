/*
 * UnUdpInterface.cpp
 *
 *  Created on: 16-Aug-2021
 *      Author: Debashis
 */

#include "unmUdpInterface.h"

unmUdpInterface::unmUdpInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "unmUdpInterface";
	this->setLogLevel(Log::theLog().level());
	this->instanceId = id;
	cleanUpCnt = 0;

	initUdpSessionPool();
	initDnsSessionPool();

	ipV4Key = 0;
	ipV6Key = "";
}

unmUdpInterface::~unmUdpInterface()
{ }

uint32_t unmUdpInterface::udpGetFreeIndex()
{
	udpFreeBitPos++;
	if(udpFreeBitPos >= udpFreeBitPosMax) udpFreeBitPos = 0;
	int arrId = udpFreeBitPos / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	int bitId = udpFreeBitPos % UNM_SESSION_POOL_ARRAY_ELEMENTS;

	while(udpBitFlagsSession[arrId].test(bitId)){
		udpFreeBitPos++;
		if(udpFreeBitPos >= udpFreeBitPosMax) udpFreeBitPos = 0;
		arrId = udpFreeBitPos / UNM_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = udpFreeBitPos % UNM_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(udpFreeBitPos >= udpFreeBitPosMax){
		printf("[%02d] getFreeIndexIp freeBitPosIp [%u] >= freeBitPosIpMax [%u]\n",instanceId, udpFreeBitPos, udpFreeBitPosMax);
	}
	udpBitFlagsSession[arrId].set(bitId);
	return udpFreeBitPos;
}

void unmUdpInterface::udpReleaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UNM_SESSION_POOL_ARRAY_ELEMENTS;

	udpSessionPoolMap[arrId][bitId]->reset();
	udpSessionPoolMap[arrId][bitId]->poolIndex = idx;
	udpBitFlagsSession[arrId].reset(bitId);
}

void unmUdpInterface::initDnsSessionPool()
{
	udpFreeBitPosMax = UNM_SESSION_POOL_ARRAY_ELEMENTS * UNM_SESSION_POOL_ARRAY_SIZE;

	printf("UnUdpInterface [%02d]	Initializing [%u]  UNM UDP Session Pool... ", instanceId, udpFreeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UDP Session Pool...", instanceId, udpFreeBitPosMax);

	for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_SIZE; i++)
	{
		udpBitFlagsSession[i].reset();
		for(uint16_t j = 0; j < UNM_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			udpSessionPoolMap[i][j] = new udpSession();
			udpSessionPoolMap[i][j]->poolIndex = (i*UNM_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UNM UDP Session Pool Completed.", instanceId, udpFreeBitPosMax);
}

udpSession* unmUdpInterface::udpGetSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / UNM_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UNM_SESSION_POOL_ARRAY_ELEMENTS;
	return udpSessionPoolMap[arrId][bitId];
}

uint32_t unmUdpInterface::getMapIndexAndSessionKey(MPacket *udpMsg)
{
	uint32_t mapIndex = 0;

    switch(udpMsg->ipVer)
    {
    	case IPVersion4:
    	{
    		mapIndex = udpMsg->sIp % UNM_SESSION_POOL_ARRAY_ELEMENTS;
    	}
    	break;
	}
	return mapIndex;
}

void unmUdpInterface::UDPPacketEntry(MPacket *udpMsg)
{
	bool found = false;

	udpSession *pUdpSession = udpGetSession(udpMsg, &found, true);

	/* Couldn't Create Session */
	if(pUdpSession == NULL) return;

	timeStampArrivalPacket(pUdpSession, udpMsg);

	/* Create New Session */
	if(!found)
	{
		initializeUdpSession(pUdpSession, udpMsg);
		updateUdpSession(pUdpSession, udpMsg);
	}
	else
	{ updateUdpSession(pUdpSession, udpMsg); }

	pUdpSession = NULL;
}

udpSession* unmUdpInterface::udpGetSession(MPacket *udpMsg, bool *found, bool create)
{
	uint32_t sessionCnt = 0;
	udpSession *pUdpSession = NULL;
	uint32_t mapIndex = 0, poolIndex = 0;

	mapIndex = getMapIndexAndSessionKey(udpMsg);

    switch(udpMsg->ipVer)
    {
    	case IPVersion4:
		{
			std::map<uint64_t, uint32_t>::iterator it = udpV4SessionMap[mapIndex].find(ipV4Key);

			if(it != udpV4SessionMap[mapIndex].end())
			{
				pUdpSession = udpGetSessionFromPool(it->second);
				*found = true;
			}
			else
			{
				if(create)
				{
					for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
						sessionCnt += (udpV4SessionMap[i].size());

					if(sessionCnt < udpFreeBitPosMax)
					{
						poolIndex = udpGetFreeIndex();
						pUdpSession = udpGetSessionFromPool(poolIndex);
						pUdpSession->reset();

						pUdpSession->ipV4sessionKey = ipV4Key;
						pUdpSession->smInstanceId = this->instanceId;
						pUdpSession->mapIndex = mapIndex;
						pUdpSession->poolIndex = poolIndex;
						udpV4SessionMap[pUdpSession->mapIndex][pUdpSession->ipV4sessionKey] = poolIndex;
					}
				}
				*found = false;
			}
		}
		break;
	}
	return pUdpSession;
}

void unmUdpInterface::initializeUdpSession(udpSession *pUdpSession, MPacket *udpMsg)
{
	pUdpSession->ipVer = udpMsg->ipVer;
	pUdpSession->protocolType = PACKET_IPPROTO_UDP;
	pUdpSession->sliceCounter = 0;

	switch(udpMsg->ipVer)
	{
	  case IPVersion4:
		  	  pUdpSession->sIpv4 = udpMsg->sIp;
		  	  pUdpSession->dIpv4 = udpMsg->dIp;
		  	  break;
	}

	pUdpSession->sPort = udpMsg->sPort;
	pUdpSession->dPort = udpMsg->dPort;

	pUdpSession->startTimeEpochSec 		= pUdpSession->pckArivalTimeEpochSec;
	pUdpSession->startTimeEpochNanoSec 	= pUdpSession->pckLastTimeEpochNanoSec;
	pUdpSession->endTimeEpochNanoSec 	= pUdpSession->pckLastTimeEpochNanoSec;
}

void unmUdpInterface::updateUdpSession(udpSession *pUdpSession, MPacket *udpMsg)
{
	uint64_t timeDiff = 0;

	pUdpSession->endTimeEpochNanoSec = udpMsg->frTimeEpochNanoSec;

	pUdpSession->frCount += 1;
	pUdpSession->frSize += udpMsg->frSize;

	if(udpMsg->pLoad > 0) {
		pUdpSession->pLoadPkt += 1;
		pUdpSession->pLoadSize +=  udpMsg->pLoad;
	}

	/** Check the Data Slicing **/
	if(pUdpSession->frCount >= Global::SESSION_PKT_LIMIT)
	{
		pUdpSession->causeCode = SYSTEM_PKTLIMIT_UDP_DATA;
		udpFlushSession(5, pUdpSession, true);
	}
	else
	{
		if(pUdpSession->pckLastTimeEpochSec > pUdpSession->startTimeEpochSec){
			timeDiff = pUdpSession->pckLastTimeEpochSec - pUdpSession->startTimeEpochSec;

			if (timeDiff >= Global::SESSION_TIME_LIMIT) {
				pUdpSession->causeCode = SYSTEM_TIMEOUT_UDP_DATA;

				udpFlushSession(9, pUdpSession, true);
			}
		}
	}
}

void unmUdpInterface::timeStampArrivalPacket(udpSession *pIpSession, MPacket *msgObj)
{
	pIpSession->pckArivalTimeEpochSec 	= msgObj->frTimeEpochSec;
	pIpSession->pckLastTimeEpochSec 	= msgObj->frTimeEpochSec;
	pIpSession->pckLastTimeEpochNanoSec = msgObj->frTimeEpochNanoSec;
}

void unmUdpInterface::udpFlushSession(uint16_t flushOrgId, udpSession *pUdpSession, bool erase)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	pUdpSession->sliceCounter += 1;
	udpStoreSession(idx, pUdpSession);

	if(erase)
		udpEraseSession(pUdpSession);
}

void unmUdpInterface::udpStoreSession(uint16_t idx, udpSession *pUdpSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_UNM_FLUSHER;

	flusherStore::uudp[flusherNo][instanceId][idx][flusherStore::uudpCnt[flusherNo][instanceId][idx]].copy(pUdpSession);
	flusherStore::uudpCnt[flusherNo][instanceId][idx]++;
}

void unmUdpInterface::udpTimeOutClean()
{
	cleanUpCnt = 0;
	uint32_t totalCount = 0;

	IPStats::smUnUdpSessionCnt[instanceId] 		= 0;
	IPStats::smUnUdpSessionScan[instanceId] 	= 0;
	IPStats::smUnUdpSessionClean[instanceId] 	= 0;

	for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::smUnUdpSessionCnt[instanceId] += udpV4SessionMap[i].size();


	for(uint16_t i = 0; i < UNM_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		for(auto elem = udpV4SessionMap[i].begin(), next_elem = elem; elem != udpV4SessionMap[i].end(); elem = next_elem)
		{
			++next_elem;
			udpCleanSession(udpGetSessionFromPool(elem->second));
			IPStats::smUnUdpSessionScan[instanceId]++;
		}
	}
	cleanUpCnt = 0;
}

void unmUdpInterface::udpCleanSession(udpSession *pUdpSession)
{
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;

	if((curEpochSec - pUdpSession->endTimeEpochNanoSec) > Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC)
	{
		pUdpSession->causeCode = SYSTEM_CLEANUP_UDP_DATA;
		IPStats::smUnUdpSessionClean[instanceId]++;
		cleanUpCnt++;
		udpFlushSession(7, pUdpSession, true);
	}
}

void unmUdpInterface::udpEraseSession(udpSession *pUdpSession)
{
	uint32_t idx, poolIndex;

	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			uint64_t sKey4 = pUdpSession->ipV4sessionKey;
			idx = pUdpSession->mapIndex;
			poolIndex = pUdpSession->poolIndex;
			udpReleaseIndex(poolIndex);
			udpV4SessionMap[idx].erase(sKey4);
		}
		break;
	}
}


/*
*  DNS Function Session
*/

uint32_t unmUdpInterface::getFreeIndexDns()
{
	freeBitPosDns++;
	if(freeBitPosDns >= freeBitPosDnsMax) freeBitPosDns = 0;
	int arrId = freeBitPosDns / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	int bitId = freeBitPosDns % DNS_SESSION_POOL_ARRAY_ELEMENTS;

	while(bitFlagsDnsSession[arrId].test(bitId)){
		freeBitPosDns++;
		if(freeBitPosDns >= freeBitPosDnsMax) freeBitPosDns = 0;
		arrId = freeBitPosDns / DNS_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = freeBitPosDns % DNS_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(freeBitPosDns >= freeBitPosDnsMax){
		printf("[%d] getFreeIndexDns freeBitPosDns [%d] >= freeBitPosDnsMax [%d]\n",instanceId, freeBitPosDns, freeBitPosDnsMax);
	}
	bitFlagsDnsSession[arrId].set(bitId);
	return freeBitPosDns;
}

void unmUdpInterface::releaseIndexDns(uint32_t idx)
{
	uint32_t arrId = idx / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % DNS_SESSION_POOL_ARRAY_ELEMENTS;

	dnsSessionPoolMap[arrId][bitId]->reset();
	dnsSessionPoolMap[arrId][bitId]->poolIndex = idx;
	bitFlagsDnsSession[arrId].reset(bitId);
}

void unmUdpInterface::initUdpSessionPool()
{
	freeBitPosDnsMax = DNS_SESSION_POOL_ARRAY_ELEMENTS * DNS_SESSION_POOL_ARRAY_SIZE;

	printf("UnUdpInterface [%02d]	Initializing [%d] DNS Session Pool... ", instanceId, freeBitPosDnsMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] DNS Session Pool...", instanceId, freeBitPosDnsMax);

	for(uint16_t i = 0; i < DNS_SESSION_POOL_ARRAY_SIZE; i++)
	{
		bitFlagsDnsSession[i].reset();
		for(uint16_t j = 0; j < DNS_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			dnsSessionPoolMap[i][j] = new dnsSession();
			dnsSessionPoolMap[i][j]->poolIndex = (i*DNS_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] DNS Session Pool Completed.", instanceId, freeBitPosDnsMax);
}

dnsSession* unmUdpInterface::getDnsSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % DNS_SESSION_POOL_ARRAY_ELEMENTS;
	return dnsSessionPoolMap[arrId][bitId];
}

void unmUdpInterface::DNSPacketEntry(MPacket *msgObj)
{
	dnsSession *pDnsSession;
	uint64_t ipV4key;
	string	ipV6key;

	/*
	 * DNS Session Key = Subs Ip + Subs Port + DNS Server Ip + Transaction Id
	 */
	switch(msgObj->qrFlag)
	{
		case QUERY:
			{
				switch(msgObj->ipVer)
				{
					case IPVersion4:
					{
						getIpv4DNSSessionKey(ipV4key, msgObj->sIp, msgObj->sPort, msgObj->dIp, msgObj->transactionId);

						std::map<uint64_t, uint32_t>::iterator it4 = ipV4dnsSessionMap.find(ipV4key);
						if(it4 != ipV4dnsSessionMap.end())
						{
							pDnsSession = getDnsSessionFromPool(it4->second);

							if(pDnsSession->state == RESPONSE)	{ //Response has arrieved before Req
								requestUpdateDnsSession(pDnsSession, msgObj);
								pDnsSession->state = SUCCESS;
								flushDnsSession(pDnsSession, SYSTEM_DNS_FLUSH_RSP_REQ);
								releaseIndexDns(pDnsSession->poolIndex);
								ipV4dnsSessionMap.erase(ipV4key);
								return;
							}
							else {	//Duplicate DNS Request seems
								uint32_t poolIndex = pDnsSession->poolIndex;
								pDnsSession->reset();
								pDnsSession->poolIndex = poolIndex;
								pDnsSession->dnsSessionV4Key = ipV4key;
								requestUpdateDnsSession(pDnsSession, msgObj);
							}
						}
						else
						{
							if((ipV4dnsSessionMap.size() + ipV6dnsSessionMap.size()) < freeBitPosDnsMax)
							{
								uint32_t poolIndex = getFreeIndexDns();
								pDnsSession = getDnsSessionFromPool(poolIndex);
								pDnsSession->reset();
								pDnsSession->poolIndex = poolIndex;
								requestUpdateDnsSession(pDnsSession, msgObj);
								pDnsSession->dnsSessionV4Key = ipV4key;
								ipV4dnsSessionMap[pDnsSession->dnsSessionV4Key] = poolIndex;
							}
						}
					}
					break;

//					case IPVersion6:
//					{
//						getIpv6DNSSessionKey(ipV6key, msgObj->sIpv6, msgObj->transactionId, msgObj->sPort);
//
//						std::map<string, uint32_t>::iterator it6 = ipV6dnsSessionMap.find(ipV6key);
//						if(it6 != ipV6dnsSessionMap.end())
//						{
//							pDnsSession = getDnsSessionFromPool(it6->second);
//
//							if(pDnsSession->state == RESPONSE)	{ //Response has arrieved before Req
//								requestUpdateDnsSession(pDnsSession, msgObj);
//								pDnsSession->state = SUCCESS;
//								flushDnsSession(pDnsSession, DNS_FLUSH_RSP_REQ);
//								releaseIndexDns(pDnsSession->poolIndex);
//								ipV6dnsSessionMap.erase(ipV6key);
//								return;
//							}
//							else {	//Duplicate DNS Request seems
//								uint32_t poolIndex = pDnsSession->poolIndex;
//								pDnsSession->reset();
//								pDnsSession->poolIndex = poolIndex;
//								pDnsSession->dnsSessionV6Key = ipV6key;
//								requestUpdateDnsSession(pDnsSession, msgObj);
//							}
//						}
//						else
//						{
//							if((ipV4dnsSessionMap.size() + ipV6dnsSessionMap.size()) < freeBitPosDnsMax)
//							{
//								uint32_t poolIndex = getFreeIndexDns();
//								pDnsSession = getDnsSessionFromPool(poolIndex);
//								pDnsSession->reset();
//								pDnsSession->poolIndex = poolIndex;
//								requestUpdateDnsSession(pDnsSession, msgObj);
//								pDnsSession->dnsSessionV6Key = ipV6key;
//								ipV6dnsSessionMap[pDnsSession->dnsSessionV6Key] = poolIndex;
//							}
//						}
//					}
//					break;

					default:
						return;
						break;
				}
			}
			break;

		case RESPONSE:
			{
				switch(msgObj->ipVer)
				{
					case IPVersion4:
					{
								getIpv4DNSSessionKey(ipV4key, msgObj->dIp, msgObj->dPort, msgObj->sIp, msgObj->transactionId);

								std::map<uint64_t, uint32_t>::iterator it4 = ipV4dnsSessionMap.find(ipV4key);

								if(it4 != ipV4dnsSessionMap.end())
								{
									pDnsSession = getDnsSessionFromPool(it4->second);

									if(pDnsSession->state == QUERY) {
										responseUpdateDnsSession(pDnsSession, msgObj);
										pDnsSession->state = SUCCESS;
										flushDnsSession(pDnsSession, SYSTEM_DNS_FLUSH_REQ_RSP);
										releaseIndexDns(pDnsSession->poolIndex);
										ipV4dnsSessionMap.erase(ipV4key);
									}
									else {	//Duplicate DNS Response seems
										uint32_t poolIndex = pDnsSession->poolIndex;
										pDnsSession->reset();
										pDnsSession->poolIndex = poolIndex;
										pDnsSession->dnsSessionV4Key = ipV4key;
										responseUpdateDnsSession(pDnsSession, msgObj);
									}
								}
								else
								{
									if((ipV4dnsSessionMap.size() + ipV6dnsSessionMap.size()) < freeBitPosDnsMax)
									{
										uint32_t poolIndex = getFreeIndexDns();
										pDnsSession = getDnsSessionFromPool(poolIndex);
										pDnsSession->reset();
										pDnsSession->poolIndex = poolIndex;
										responseUpdateDnsSession(pDnsSession, msgObj);
										pDnsSession->dnsSessionV4Key = ipV4key;
										ipV4dnsSessionMap[pDnsSession->dnsSessionV4Key] = poolIndex;
									}
								}
					}
					break;

//					case IPVersion6:
//					{
//								getIpv6DNSSessionKey(ipV6key, msgObj->dIpv6, msgObj->transactionId, msgObj->dPort);
//
//								std::map<string, uint32_t>::iterator it6 = ipV6dnsSessionMap.find(ipV6key);
//
//								if(it6 != ipV6dnsSessionMap.end())
//								{
//									pDnsSession = getDnsSessionFromPool(it6->second);
//
//									if(pDnsSession->state == QUERY) {
//										responseUpdateDnsSession(pDnsSession, msgObj);
//										pDnsSession->state = SUCCESS;
//										flushDnsSession(pDnsSession, DNS_FLUSH_REQ_RSP);
//										releaseIndexDns(pDnsSession->poolIndex);
//										ipV6dnsSessionMap.erase(ipV6key);
//									}
//									else {	//Duplicate DNS Response seems
//										uint32_t poolIndex = pDnsSession->poolIndex;
//										pDnsSession->reset();
//										pDnsSession->poolIndex = poolIndex;
//										pDnsSession->dnsSessionV6Key = ipV6key;
//										responseUpdateDnsSession(pDnsSession, msgObj);
//									}
//								}
//								else
//								{
//									if((ipV4dnsSessionMap.size() + ipV6dnsSessionMap.size()) < freeBitPosDnsMax)
//									{
//										uint32_t poolIndex = getFreeIndexDns();
//										pDnsSession = getDnsSessionFromPool(poolIndex);
//										pDnsSession->reset();
//										pDnsSession->poolIndex = poolIndex;
//										responseUpdateDnsSession(pDnsSession, msgObj);
//										pDnsSession->dnsSessionV6Key = ipV6key;
//										ipV6dnsSessionMap[pDnsSession->dnsSessionV6Key] = poolIndex;
//									}
//								}
//					}
//					break;

					default:
								return;
								break;
				}
			}
			break;

		default:
			break;
	}
}

void unmUdpInterface::requestUpdateDnsSession(dnsSession *pDnsSession, MPacket *msgObj)
{
	pDnsSession->ipVer					= msgObj->ipVer;
	pDnsSession->transactionId 			= msgObj->transactionId;

	pDnsSession->queryStartEpochSec 	= msgObj->frTimeEpochSec;
	pDnsSession->queryStartEpochNanoSec = msgObj->frTimeEpochNanoSec;
	pDnsSession->queryEndEpochSec 		= msgObj->frTimeEpochSec;
	pDnsSession->queryEndEpochNanoSec 	= msgObj->frTimeEpochNanoSec;

	switch(msgObj->ipVer)
	{
		case IPVersion4:
				pDnsSession->sIpv4 	= msgObj->sIp;
				pDnsSession->dIpv4 	= msgObj->dIp;
				break;
	}

	pDnsSession->sourcePort 			= msgObj->sPort;
	pDnsSession->destPort 				= msgObj->dPort;
	pDnsSession->state 					= QUERY;

	strcpy(pDnsSession->URL, msgObj->url);
}

void unmUdpInterface::responseUpdateDnsSession(dnsSession *pDnsSession, MPacket *msgObj)
{
	if(pDnsSession->ipVer == 0) 		pDnsSession->ipVer 			= msgObj->ipVer;
	pDnsSession->transactionId 			= msgObj->transactionId;
	pDnsSession->queryEndEpochSec 		= msgObj->frTimeEpochSec;
	pDnsSession->queryEndEpochNanoSec 	= msgObj->frTimeEpochNanoSec;

	switch(msgObj->ipVer)
	{
		case IPVersion4:

			if(pDnsSession->sIpv4 == 0) pDnsSession->sIpv4 	= msgObj->sIp;
			if(pDnsSession->dIpv4 == 0)	pDnsSession->dIpv4 	= msgObj->dIp;
				break;
	}

	if(msgObj->responseCode <= 26)
	{
		pDnsSession->errorCode 			= msgObj->responseCode;
		strcpy(pDnsSession->errorDesc, initalize::dnsErrorCode[msgObj->responseCode].c_str());
	}
	else
		pDnsSession->errorCode 			= 24;

	if(pDnsSession->sourcePort == 0) pDnsSession->sourcePort 	= msgObj->sPort;
	if(pDnsSession->destPort == 0)   pDnsSession->destPort 		= msgObj->dPort;
	pDnsSession->state 					= RESPONSE;

	if(strlen(pDnsSession->URL) == 0 && strlen(msgObj->url) != 0)
		strcpy(pDnsSession->URL, msgObj->url);
}

void unmUdpInterface::getIpv4DNSSessionKey(uint64_t &key, uint32_t userAddrLong, uint16_t port, uint32_t destAddrLong, uint32_t dnsTransactionId)
{ key = (userAddrLong^4) + (port^3) + (destAddrLong^2) + (dnsTransactionId^1); }

void unmUdpInterface::getIpv6DNSSessionKey(std::string &key, char* userAddrLong, uint32_t dnsTransactionId, uint16_t port)
{ key = userAddrLong + to_string(port) + to_string(dnsTransactionId); }

void unmUdpInterface::flushDnsSession(dnsSession *pDnsSession, uint16_t type)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	pDnsSession->flushType = type;

	storeDnsSession(idx, pDnsSession);
}

void unmUdpInterface::storeDnsSession(uint16_t idx, dnsSession *pDnsSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_UNM_FLUSHER;

	flusherStore::udns[flusherNo][instanceId][idx][flusherStore::udnsCnt[flusherNo][instanceId][idx]].copy(pDnsSession);
	flusherStore::udnsCnt[flusherNo][instanceId][idx]++;

}

void unmUdpInterface::dnsTimeOutClean()
{
	uint16_t IdleTimeSec = Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC;

	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;
	uint16_t flushType = 0;

	dnsSessionCleanUpMap_cnt = 0;

	for(auto elem : ipV4dnsSessionMap)
	{
		dnsSession *pDnsSession = getDnsSessionFromPool(elem.second);

		if(((pDnsSession->queryStartEpochSec > 0) && ((curEpochSec - pDnsSession->queryStartEpochSec) > IdleTimeSec)) ||
				((pDnsSession->queryEndEpochSec > 0) && ((curEpochSec - pDnsSession->queryEndEpochSec) > IdleTimeSec)))
		{
			if(pDnsSession->queryStartEpochSec == 0 && pDnsSession->queryEndEpochSec != 0)
			{
				pDnsSession->queryStartEpochSec = pDnsSession->queryEndEpochSec;
				pDnsSession->queryStartEpochNanoSec = pDnsSession->queryEndEpochNanoSec;
				flushType = SYSTEM_CLEANUP_DNS_RSP;
			}
			else if(pDnsSession->queryEndEpochSec == 0 && pDnsSession->queryStartEpochSec != 0)
			{
				pDnsSession->queryEndEpochSec = pDnsSession->queryStartEpochSec;
				pDnsSession->queryEndEpochNanoSec = pDnsSession->queryStartEpochNanoSec;
				flushType = SYSTEM_CLEANUP_DNS_QUERY;
			}
			else
			{ flushType = SYSTEM_CLEANUP_DNS_REQ_RSP; }

			pDnsSession->causeCode = SYSTEM_CLEANUP_DNS_QUERY;

			if(pDnsSession->state == QUERY)
			{
				pDnsSession->errorCode = SYSTEM_CLEANUP_DNS_QUERY;
				strcpy(pDnsSession->errorDesc, "No Response");
			}
			/* Flush only DNS Request Message (As No Response is only for Request) */
			if(strlen(pDnsSession->URL) != 0 && pDnsSession->state != RESPONSE) flushDnsSession(pDnsSession, flushType);
			dnsSessionCleanUpMap[dnsSessionCleanUpMap_cnt].ipv4key = elem.first;
			dnsSessionCleanUpMap[dnsSessionCleanUpMap_cnt].poolIndex = elem.second;
			dnsSessionCleanUpMap_cnt++;
		}
	}

	for(uint32_t i = 0; i < dnsSessionCleanUpMap_cnt; i++)
	{
		releaseIndexDns(dnsSessionCleanUpMap[i].poolIndex);
		ipV4dnsSessionMap.erase(dnsSessionCleanUpMap[i].ipv4key);
	}

	dnsSessionCleanUpMap.clear();
	dnsSessionCleanUpMap_cnt = 0;

//	/*** IPV6 ***/
//
//	for(auto elem : ipV6dnsSessionMap)
//	{
//		dnsSession *pDnsSession = getDnsSessionFromPool(elem.second);
//
//		if(((pDnsSession->queryStartEpochSec > 0) && ((curEpochSec - pDnsSession->queryStartEpochSec) > IdleTimeSec)) ||
//				((pDnsSession->queryEndEpochSec > 0) && ((curEpochSec - pDnsSession->queryEndEpochSec) > IdleTimeSec)))
//		{
//			if(pDnsSession->queryStartEpochSec == 0 && pDnsSession->queryEndEpochSec != 0)
//			{
//				pDnsSession->queryStartEpochSec = pDnsSession->queryEndEpochSec;
//				pDnsSession->queryStartEpochNanoSec = pDnsSession->queryEndEpochNanoSec;
//				flushType = SYSTEM_CLEANUP_DNS_RSP;
//			}
//			else if(pDnsSession->queryEndEpochSec == 0 && pDnsSession->queryStartEpochSec != 0)
//			{
//				pDnsSession->queryEndEpochSec = pDnsSession->queryStartEpochSec;
//				pDnsSession->queryEndEpochNanoSec = pDnsSession->queryStartEpochNanoSec;
//				flushType = SYSTEM_CLEANUP_DNS_QUERY;
//			}
//			else
//			{ flushType = SYSTEM_CLEANUP_DNS_REQ_RSP; }
//
//			pDnsSession->causeCode = SYSTEM_CLEANUP_DNS_QUERY;
//
//			if(pDnsSession->state == QUERY)
//			{
//				pDnsSession->errorCode = SYSTEM_CLEANUP_DNS_QUERY;
//				strcpy(pDnsSession->errorDesc, "No Response");
//			}
//			/* Flush only DNS Request Message (As No Response is only for Request) */
//			if(strlen(pDnsSession->URL) != 0 && pDnsSession->state != RESPONSE) flushDnsSession(pDnsSession, flushType);
//			dnsSessionCleanUpMap[dnsSessionCleanUpMap_cnt].ipv6key = elem.first;
//			dnsSessionCleanUpMap[dnsSessionCleanUpMap_cnt].poolIndex = elem.second;
//			dnsSessionCleanUpMap_cnt++;
//		}
//	}
//
//	for(uint32_t i = 0; i < dnsSessionCleanUpMap_cnt; i++)
//	{
//		releaseIndexDns(dnsSessionCleanUpMap[i].poolIndex);
//		ipV6dnsSessionMap.erase(dnsSessionCleanUpMap[i].ipv6key);
//	}
//
//	dnsSessionCleanUpMap.clear();
//	dnsSessionCleanUpMap_cnt = 0;
}
