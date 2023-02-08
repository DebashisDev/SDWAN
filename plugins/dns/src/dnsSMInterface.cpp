/*
 * dnsSMInterface.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: Debashis
 */

#include "dnsSMInterface.h"

dnsSMInterface::dnsSMInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "dnsSMInterface";
	this->setLogLevel(Log::theLog().level());

	this->instanceId = id;
	this->ipV4Key = 0;
	this->ipV6Key = "";
	this->freeBitPos = 0;
	this->freeBitPosMax = 0;

	initializeSessionPool();
}

dnsSMInterface::~dnsSMInterface()
{

}

uint32_t dnsSMInterface::getFreeIndex()
{
	freeBitPos++;
	if(freeBitPos >= freeBitPosMax) freeBitPos = 0;
	uint32_t arrId = freeBitPos / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = freeBitPos % DNS_SESSION_POOL_ARRAY_ELEMENTS;

	while(bitFlagsSession[arrId].test(bitId))
	{
		freeBitPos++;
		if(freeBitPos >= freeBitPosMax) freeBitPos = 0;
		arrId = freeBitPos / DNS_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = freeBitPos % DNS_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(freeBitPos >= freeBitPosMax){
		printf("[%d] getFreeIndex freeBitPos [%u] >= freeBitPosMax [%u]\n",instanceId, freeBitPos, freeBitPosMax);
	}
	bitFlagsSession[arrId].set(bitId);
	return freeBitPos;
}

void dnsSMInterface::releaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % DNS_SESSION_POOL_ARRAY_ELEMENTS;
	sessionPoolMap[arrId][bitId]->reset();
	sessionPoolMap[arrId][bitId]->poolIndex = idx;
	bitFlagsSession[arrId].reset(bitId);
}

void dnsSMInterface::initializeSessionPool()
{
	freeBitPosMax = DNS_SESSION_POOL_ARRAY_ELEMENTS * DNS_SESSION_POOL_ARRAY_SIZE;

	printf("dnsSMInterface [%02d]	Initializing [%u] DNS Session Pool... ", instanceId, freeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] DNS Session Pool...", instanceId, freeBitPosMax);
	for(uint16_t i = 0; i < DNS_SESSION_POOL_ARRAY_SIZE; i++)
	{
		bitFlagsSession[i].reset();
		for(uint16_t j = 0; j < DNS_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			sessionPoolMap[i][j] = new dnsSession();
			sessionPoolMap[i][j]->poolIndex = (i*DNS_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] DNS Session Pool Completed.", instanceId, freeBitPosMax);
}

dnsSession* dnsSMInterface::getSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / DNS_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % DNS_SESSION_POOL_ARRAY_ELEMENTS;
	return sessionPoolMap[arrId][bitId];
}

void dnsSMInterface::DnsPacketEntry(MPacket *udpMsg)
{
	dnsSession*	pDnsSession;
	uint64_t 	ipV4key;
	string		ipV6key;

	if(udpMsg == NULL)
		return;

	switch(udpMsg->qrFlag)
	{
		case QUERY:
		{
			switch(udpMsg->ipVer)
			{
				case IPVersion4:
				{
					getIpv4SessionKey(ipV4key, udpMsg->sIp, udpMsg->sPort, udpMsg->dIp, udpMsg->transactionId);

					std::map<uint64_t, uint32_t>::iterator it4 = dnsV4SessionMap.find(ipV4key);

					if(it4 != dnsV4SessionMap.end())
					{
						pDnsSession = getSessionFromPool(it4->second);

						if(pDnsSession->state == RESPONSE)
						{
							requestUpdateSession(pDnsSession, udpMsg);
							pDnsSession->state = SUCCESS;
							flushSession(pDnsSession, SYSTEM_DNS_FLUSH_RSP_REQ);
							releaseIndex(pDnsSession->poolIndex);
							dnsV4SessionMap.erase(ipV4key);
							return;
						}
						else
						{
							uint32_t poolIndex = pDnsSession->poolIndex;
							pDnsSession->reset();
							pDnsSession->poolIndex = poolIndex;
							pDnsSession->dnsSessionV4Key = ipV4key;
							requestUpdateSession(pDnsSession, udpMsg);
						}
					}
					else
					{
						if((dnsV4SessionMap.size() + dnsV6SessionMap.size()) < freeBitPosMax)
						{
							uint32_t poolIndex = getFreeIndex();
							pDnsSession = getSessionFromPool(poolIndex);
							pDnsSession->reset();
							pDnsSession->poolIndex = poolIndex;
							requestUpdateSession(pDnsSession, udpMsg);
							pDnsSession->dnsSessionV4Key = ipV4key;
							dnsV4SessionMap[pDnsSession->dnsSessionV4Key] = poolIndex;
						}
					}
				}
				break;

//				case IPVersion6:
//				{
//					getIpv6SessionKey(ipV6key, udpMsg->sIpv6, udpMsg->transactionId, udpMsg->sPort);
//
//					std::map<string, uint32_t>::iterator it6 = dnsV6SessionMap.find(ipV6key);
//					if(it6 != dnsV6SessionMap.end())
//					{
//						pDnsSession = getSessionFromPool(it6->second);
//
//						if(pDnsSession->state == RESPONSE)
//						{
//							requestUpdateSession(pDnsSession, udpMsg);
//							pDnsSession->state = SUCCESS;
//							flushSession(pDnsSession, DNS_FLUSH_RSP_REQ);
//							releaseIndex(pDnsSession->poolIndex);
//							dnsV6SessionMap.erase(ipV6key);
//							return;
//						}
//						else
//						{
//							uint32_t poolIndex = pDnsSession->poolIndex;
//							pDnsSession->reset();
//							pDnsSession->poolIndex = poolIndex;
//							pDnsSession->dnsSessionV6Key = ipV6key;
//							requestUpdateSession(pDnsSession, udpMsg);
//						}
//					}
//					else
//					{
//						if((dnsV4SessionMap.size() + dnsV6SessionMap.size()) < freeBitPosMax)
//						{
//							uint32_t poolIndex = getFreeIndex();
//							pDnsSession = getSessionFromPool(poolIndex);
//							pDnsSession->reset();
//							pDnsSession->poolIndex = poolIndex;
//							requestUpdateSession(pDnsSession, udpMsg);
//							pDnsSession->dnsSessionV6Key = ipV6key;
//							dnsV6SessionMap[pDnsSession->dnsSessionV6Key] = poolIndex;
//						}
//					}
//				}
//				break;

			default:
						return;
						break;
			}
		}
		break;

		case RESPONSE:
		{
			switch(udpMsg->ipVer)
			{
				case IPVersion4:
				{
					getIpv4SessionKey(ipV4key, udpMsg->dIp, udpMsg->dPort, udpMsg->sIp, udpMsg->transactionId);

					std::map<uint64_t, uint32_t>::iterator it4 = dnsV4SessionMap.find(ipV4key);

					if(it4 != dnsV4SessionMap.end())
					{
						pDnsSession = getSessionFromPool(it4->second);

						if(pDnsSession->state == QUERY)
						{
							responseUpdateSession(pDnsSession, udpMsg);
							pDnsSession->state = SUCCESS;
							flushSession(pDnsSession, SYSTEM_DNS_FLUSH_REQ_RSP);
							releaseIndex(pDnsSession->poolIndex);
							dnsV4SessionMap.erase(ipV4key);
						}
						else
						{
							uint32_t poolIndex = pDnsSession->poolIndex;
							pDnsSession->reset();
							pDnsSession->poolIndex = poolIndex;
							pDnsSession->dnsSessionV4Key = ipV4key;
							responseUpdateSession(pDnsSession, udpMsg);
						}
					}
					else
					{
						if((dnsV4SessionMap.size() + dnsV6SessionMap.size()) < freeBitPosMax)
						{
							uint32_t poolIndex = getFreeIndex();
							pDnsSession = getSessionFromPool(poolIndex);
							pDnsSession->reset();
							pDnsSession->poolIndex = poolIndex;
							responseUpdateSession(pDnsSession, udpMsg);
							pDnsSession->dnsSessionV4Key = ipV4key;
							dnsV4SessionMap[pDnsSession->dnsSessionV4Key] = poolIndex;
						}
					}
				}
				break;

//				case IPVersion6:
//				{
//					getIpv6SessionKey(ipV6key, udpMsg->dIpv6, udpMsg->transactionId, udpMsg->dPort);
//
//					std::map<string, uint32_t>::iterator it6 = dnsV6SessionMap.find(ipV6key);
//
//					if(it6 != dnsV6SessionMap.end())
//					{
//						pDnsSession = getSessionFromPool(it6->second);
//
//						if(pDnsSession->state == QUERY)
//						{
//							responseUpdateSession(pDnsSession, udpMsg);
//							pDnsSession->state = SUCCESS;
//							flushSession(pDnsSession, DNS_FLUSH_REQ_RSP);
//							releaseIndex(pDnsSession->poolIndex);
//							dnsV6SessionMap.erase(ipV6key);
//						}
//						else
//						{
//							uint32_t poolIndex = pDnsSession->poolIndex;
//							pDnsSession->reset();
//							pDnsSession->poolIndex = poolIndex;
//							pDnsSession->dnsSessionV6Key = ipV6key;
//							responseUpdateSession(pDnsSession, udpMsg);
//						}
//					}
//					else
//					{
//						if((dnsV4SessionMap.size() + dnsV6SessionMap.size()) < freeBitPosMax)
//						{
//							uint32_t poolIndex = getFreeIndex();
//							pDnsSession = getSessionFromPool(poolIndex);
//							pDnsSession->reset();
//							pDnsSession->poolIndex = poolIndex;
//							responseUpdateSession(pDnsSession, udpMsg);
//							pDnsSession->dnsSessionV6Key = ipV6key;
//							dnsV6SessionMap[pDnsSession->dnsSessionV6Key] = poolIndex;
//						}
//					}
//				}
//				break;

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

void dnsSMInterface::requestUpdateSession(dnsSession *pDnsSession, MPacket *msgObj)
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

void dnsSMInterface::responseUpdateSession(dnsSession *pDnsSession, MPacket *msgObj)
{
	if(pDnsSession->ipVer == 0) 		pDnsSession->ipVer 			= msgObj->ipVer;
	if(pDnsSession->transactionId == 0) pDnsSession->transactionId	= msgObj->transactionId;
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
		strcpy(pDnsSession->resolvedIp, msgObj->resolvedIp);
	}
	else
		pDnsSession->errorCode 			= 24;

	if(pDnsSession->sourcePort == 0) pDnsSession->sourcePort 	= msgObj->sPort;
	if(pDnsSession->destPort == 0)   pDnsSession->destPort 		= msgObj->dPort;
	pDnsSession->state 					= RESPONSE;

	if(strlen(pDnsSession->URL) == 0 && strlen(msgObj->url) != 0)
		strcpy(pDnsSession->URL, msgObj->url);
	{

	}
}

void dnsSMInterface::getIpv4SessionKey(uint64_t &key, uint32_t userAddrLong, uint16_t port, uint32_t destAddrLong, uint32_t dnsTransactionId)
{ key = (userAddrLong^4) + (port^3) + (destAddrLong^2) + (dnsTransactionId^1); }

void dnsSMInterface::getIpv6SessionKey(std::string &key, char* userAddrLong, uint32_t dnsTransactionId, uint16_t port)
{ key = userAddrLong + to_string(port) + to_string(dnsTransactionId); }

void dnsSMInterface::flushSession(dnsSession *pDnsSession, int type)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSecNow, Global::TIME_INDEX);

	pDnsSession->flushType = type;

	storeSession(idx, pDnsSession);
}

void dnsSMInterface::storeSession(uint16_t idx, dnsSession *pDnsSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_DNS_FLUSHER;

	flusherStore::dns[flusherNo][instanceId][idx][flusherStore::dnsCnt[flusherNo][instanceId][idx]].copy(pDnsSession);
	flusherStore::dnsCnt[flusherNo][instanceId][idx]++;
}

void dnsSMInterface::sessionTimeOutClean()
{
	uint16_t IdleTimeSec = Global::DNS_SESSION_CLEAN_UP_TIMEOUT_SEC;
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;
	uint16_t flushType = 0;

	sessionCleanCnt = 0;

	IPStats::smDnsV4SessionCnt[instanceId] = dnsV4SessionMap.size();
	IPStats::smDnsV6SessionCnt[instanceId] = dnsV6SessionMap.size();

	for(auto elem : dnsV4SessionMap)
	{
		IPStats::smDnsV4SessionScan[instanceId]++;
		dnsSession *pDnsSession = getSessionFromPool(elem.second);

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
			{ flushType =	SYSTEM_CLEANUP_DNS_REQ_RSP; }

			pDnsSession->causeCode = SYSTEM_CLEANUP_DNS_QUERY;

			if(pDnsSession->state == QUERY)
			{
				pDnsSession->errorCode = SYSTEM_CLEANUP_DNS_QUERY;
				strcpy(pDnsSession->errorDesc, "No Response");
				strcpy(pDnsSession->resolvedIp, "NULL");

			}
			/* Flush only DNS Request Message (As No Response is only for Request) */
//			if(strlen(pDnsSession->URL) != 0 && pDnsSession->state != RESPONSE)
			flushSession(pDnsSession, flushType);
			sessionCleanUpMap[sessionCleanCnt].ipv4key = elem.first;
			sessionCleanUpMap[sessionCleanCnt].poolIndex = elem.second;
			sessionCleanCnt++;
		}
	}

	IPStats::smDnsV4SessionClean[instanceId] = sessionCleanCnt;

	for(uint32_t i = 0; i < sessionCleanCnt; i++)
	{
		releaseIndex(sessionCleanUpMap[i].poolIndex);
		dnsV4SessionMap.erase(sessionCleanUpMap[i].ipv4key);
	}

	sessionCleanUpMap.clear();
	sessionCleanCnt = 0;

//	/*** IPV6 ***/
//
//	for(auto elem : dnsV6SessionMap)
//	{
//		dnsSession *pDnsSession = getSessionFromPool(elem.second);
//
//		IPStats::smDnsV6SessionScan[instanceId]++;
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
//				strcpy(pDnsSession->resolvedIp, "NULL");
//			}
//			/* Flush only DNS Request Message (As No Response is only for Request) */
//			if(strlen(pDnsSession->URL) != 0 && pDnsSession->state != RESPONSE) flushSession(pDnsSession, flushType);
//			sessionCleanUpMap[sessionCleanCnt].ipv6key = elem.first;
//			sessionCleanUpMap[sessionCleanCnt].poolIndex = elem.second;
//			sessionCleanCnt++;
//		}
//	}
//
//	IPStats::smDnsV6SessionClean[instanceId] += sessionCleanCnt;
//
//	for(uint32_t i = 0; i < sessionCleanCnt; i++)
//	{
//		releaseIndex(sessionCleanUpMap[i].poolIndex);
//		dnsV6SessionMap.erase(sessionCleanUpMap[i].ipv6key);
//	}
//
//	sessionCleanUpMap.clear();
//	sessionCleanCnt = 0;
}

void dnsSMInterface::loadResolvedIpv4()
{
	string filePath = Global::DATA_DIR + "dnsIpv4data.csv";

	std::string line;
	std::string url;
	uint32_t ip;
	int loadedCnt = 0;
	char* pch;

	ifstream fp;

	fp.open(filePath.c_str());

	if(fp.fail())
	{
		TheLog_nc_v1(Log::Info, name(),"SpectaProbe Error in Loading IPv4 DNS Lookup file [%s]", filePath.c_str());
	}
	else
	{
		while(!fp.eof())
		{
			getline(fp, line);
			if(!line.empty() && line.length() > 0)
			{
				pch = strtok ((char *)line.c_str(), ",");

				if(pch == NULL) break;
				ip = atol(pch);

				pch = strtok (NULL, ",");  // Error in Here

				if(pch == NULL) break;

				url = std::string(pch);

				if(ip > 0)
				{
					loadedCnt++;
					DNSGlobal::dnsLookUpMap[ip % 10][ip] = url;
				}
			}
		}
		fp.close();
	}

	TheLog_nc_v2(Log::Info, name(),"     Loaded [ %06d ] Records in Dns IPv4 Lookup Map from file [%s]", loadedCnt, filePath.c_str());
	printf("     Loaded [ %06d ] Records in Dns IPv4 Lookup Map from file [%s].\n", loadedCnt, filePath.c_str());
}

//void dnsSMInterface::loadResolvedIpv6()
//{
//	string filePath = Global::DATA_DIR + "dnsIpv6data.csv";
//
//	std::string line;
//	std::string url;
//	std::string ip;
//
//	int loadedCnt = 0;
//	char* pch;
//
//	ifstream fp;
//
//	fp.open(filePath.c_str());
//
//	if(fp.fail())
//	{
//		TheLog_nc_v1(Log::Warn, name(),"     Error in Loading IPv6 DNS Lookup file [%s]", filePath.c_str());
//	}
//	else
//	{
//		while(!fp.eof())
//		{
//			getline(fp, line);
//
//			if(!line.empty() && line.length() > 0)
//			{
//				pch = strtok ((char *)line.c_str(), ",");
//
//				if(pch == NULL) break;
//
//				ip = std::string(pch);
//
//				pch = strtok (NULL, ",");
//
//				if(pch == NULL) break;
//				url = std::string(pch);
//
//				DNSGlobal::dnsV6LookUpMap[ip] = url;
//				loadedCnt ++;
//			}
//		}
//		fp.close();
//	}
//
//	TheLog_nc_v2(Log::Debug, name(),"     Loaded [ %06d ] Records in Dns IPv6 Lookup Map from file [%s]", loadedCnt, filePath.c_str());
//	printf("     Loaded [ %06d ] Records in Dns IPv6 Lookup Map from file [%s].\n", loadedCnt, filePath.c_str());
//}

void dnsSMInterface::dnsIpV4LookUpCount()
{
	IPStats::dnsLookupMapSize = 0;

	for(int i = 0; i < 10; i++)
		IPStats::dnsLookupMapSize += DNSGlobal::dnsLookUpMap[i].size();
}
