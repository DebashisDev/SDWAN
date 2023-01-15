/*
  * TCPFlusherUtility.cpp
 *
 *  Created on: Dec 21, 2016
 *      Author: Deb
 */

#include "flusherUtility.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string.h>


flusherUtility::flusherUtility(uint16_t instanceId)
{
}

flusherUtility::~flusherUtility()
{ }

void flusherUtility::lockDnsMap()
{
	pthread_mutex_lock(&mapDnsLock::lockCount);
	while (mapDnsLock::count == 0)
		pthread_cond_wait(&mapDnsLock::nonzero, &mapDnsLock::lockCount);
	mapDnsLock::count = mapDnsLock::count - 1;
	pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void flusherUtility::unLockDnsMap()
{
    pthread_mutex_lock(&mapDnsLock::lockCount);
    if (mapDnsLock::count == 0)
        pthread_cond_signal(&mapDnsLock::nonzero);
    mapDnsLock::count = mapDnsLock::count + 1;
    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void flusherUtility::buildUdpXdr(udpSession *pUdpSession, char *xdr)
{
	string sessionKey = "";
	string url = "NULL";

	char protoDesc[5];

	sIpAddress[0] = 0;
	dIpAddress[0] = 0;

	xdr[0] = protoDesc[0] = 0;

	/* get URL */
	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			sessionKey = to_string(pUdpSession->ipV4sessionKey);

			url = getResolvedIp4(pUdpSession->dIpv4);

			long2Ip(pUdpSession->sIpv4, sIpAddress);
			long2Ip(pUdpSession->dIpv4, dIpAddress);
		}
		break;
	}

	sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- Protocol Type,     04- Protocol Desc,
				 "%s-%d,"			// 05- Session Key,
				 "%s,%d,%s,%d,"		// 06- Source Ip,      07- Source Port,        08- Dest Ip,           09- Dest Port,
				 "%d,%d,"			// 10- VLAN Id, 	   11- Slice Counter,
			     "%d,%d,%d,"		// 12- Frame Cnt,      13- Up Frame Cnt,       14- Dn Frame Cnt,
				 "%u,%u,%u,"		// 15- Frame Size,     16- Up Frame Size,      17- Dn Frame Size,
				 "%d,%d,%d,"		// 18- Payload Pkt,    19- Up Payload Pkt,     20- Dn Payload Pkt,
				 "%u,%u,%u,"		// 21- Payload Size,   22- Up Payload Size,    23- Dn Payload Size,
				 "%lu,"			    // 24- Start Time,
				 "%d,"				// 25- Cause Code,
				 "%s,"				// 26- URL,
				 "%d,%lu,"			// 27- Flush Id		   28- Flush time
				 "%d",				// 29- Ip version

			Global::PROBE_ID, IP_XDR_ID, pUdpSession->protocolType, initalize::protocolName[pUdpSession->protocolType].c_str(),
			sessionKey.c_str(), pUdpSession->sliceCounter,
			sIpAddress, pUdpSession->sPort, dIpAddress, pUdpSession->dPort,
			0, pUdpSession->sliceCounter,
			pUdpSession->frCount, pUdpSession->upFrCount, pUdpSession->dnFrCount,
			pUdpSession->frSize, pUdpSession->upFrSize, pUdpSession->dnFrSize,
			pUdpSession->pLoadPkt, pUdpSession->upPLoadPkt, pUdpSession->dnPLoadPkt,
			pUdpSession->pLoadSize, pUdpSession->upPLoadSize, pUdpSession->dnPLoadSize,
			pUdpSession->startTimeEpochNanoSec,
			pUdpSession->causeCode,
			url.c_str(),
			pUdpSession->flushOrgId, pUdpSession->flushTime,
			pUdpSession->ipVer);
}

void flusherUtility::buildTcpXdr(tcpSession *pTcpSession, char *xdr)
{
	string sessionKey = "";
	string url;

	ULONG dataLatency = 0;
	ULONG sumWeightage = 0;
	char protoDesc[5];
	xdr[0] = protoDesc[0] = 0;
	bool writeXDRFlag = true;

	sIpAddress[0] = 0;
	dIpAddress[0] = 0;


	std::size_t found;

	/* get URL */
	switch(pTcpSession->ipVer)
	{
		case IPVersion4:
		{
			sessionKey 	= to_string(pTcpSession->ipV4sessionKey);
			url = getResolvedIp4(pTcpSession->dIpv4);

			long2Ip(pTcpSession->sIpv4, sIpAddress);
			long2Ip(pTcpSession->dIpv4, dIpAddress);
		}
		break;
	}

	if(!someChecks(pTcpSession)) return;

		sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- Protocol Type,     04- Protocol Desc,
					 "%s-%d,"			// 05- Session Key,
					 "%s,%d,%s,%d,"		// 06- Source Ip,      07- Source Port,        08- Dest Ip,           09- Dest Port,
					 "%d,%d,"			// 10- VLAN Id, 	   11- Slice Counter,
					 "%d,%d,%d,"		// 12- Frame Cnt,      13- Up Frame Cnt,       14- Dn Frame Cnt,
					 "%u,%u,%u,"		// 15- Frame Size,     16- Up Frame Size,      17- Dn Frame Size,
					 "%d,%d,%d,"		// 18- Payload Pkt,    19- Up Payload Pkt,     20- Dn Payload Pkt,
					 "%u,%u,%u,"		// 21- Payload Size,   22- Up Payload Size,    23- Dn Payload Size,
					 "%lu,"			    // 24- Start Time,
					 "%d,"				// 26- Cause Code,
					 "%s,"				// 27- URL,
					 "%d,%u,"			// 28- Flush Id		   29- Flush time
					 "%d",				// 30- Ip version

				Global::PROBE_ID, IP_XDR_ID, pTcpSession->protocolType, initalize::protocolName[pTcpSession->protocolType].c_str(),
				sessionKey.c_str(), pTcpSession->sliceCounter,
				sIpAddress, pTcpSession->sPort, dIpAddress, pTcpSession->dPort,
				0, pTcpSession->sliceCounter,
				pTcpSession->frCount, pTcpSession->upFrCount, pTcpSession->dnFrCount,
				pTcpSession->frSize, pTcpSession->upFrSize, pTcpSession->dnFrSize,
				pTcpSession->pLoadPkt, pTcpSession->upPLoadPkt, pTcpSession->dnPLoadPkt,
				pTcpSession->pLoadSize, pTcpSession->upPLoadSize, pTcpSession->dnPLoadSize,
				pTcpSession->startTimeEpochNanoSec,
				pTcpSession->causeCode,
				url.c_str(),
				pTcpSession->flushOrgId, pTcpSession->flushTime,
				pTcpSession->ipVer);

}

bool flusherUtility::someChecks(tcpSession *pIpSession)
{
	bool xdrProcess = true;

	/* These Checkes are for Spike in TP */
	if(pIpSession->frSize < pIpSession->pLoadSize)
	{
		xdrProcess = false;
		return xdrProcess;
	}
	return xdrProcess;
}

void flusherUtility::swap3(uint64_t *a, uint64_t *b, uint64_t *c)
{
	uint64_t lr, mi, sm;

	if(*a > *b)
	{
		mi = *a;
		sm = *b;
	}
	else
	{
		mi = *b;
		sm = *a;
	}

	if(mi > *c)
	{
		lr = mi;
		if(sm > *c)
		{
			mi = sm;
			sm = *c;
		}
		else
		{
			mi = *c;
		}
	}
	else
		lr = *c;

	*a = sm;
	*b = mi;
	*c = lr;
}

void flusherUtility::swap4(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
	uint64_t temp = 0; ;

	if(*a > *b)
	{
		temp = *a;
		*a = *b;
		*b = temp;
	}
	if(*c > *d)
	{
		temp = *c;
		*c = *d;
		*d = temp;
	}
	if(*a > *c)
	{
		temp = *a;
		*a = *c;
		*c = temp;
	}
	if(*b > *d)
	{
		temp = *b;
		*b = *d;
		*d = temp;
	}
	if(*b > *c)
	{
		temp = *b;
		*b = *c;
		*c = temp;
	}
}

void flusherUtility::buildDnsXdr(dnsSession *pDnsSession, char *csvXDR)
{
	uint32_t dnsResTimeMilliSec = 0;
	string sessionKey = "";

	uint64_t sTime = pDnsSession->queryStartEpochNanoSec;
	uint64_t eTime = pDnsSession->queryEndEpochNanoSec;

	csvXDR[0] = 0;

	if(eTime > 0 && sTime > 0 && (eTime > sTime)) {
		if(sTime > 1000000) {
			sTime = sTime / (1000 * 1000);
			if(eTime > 1000000) {
				eTime = eTime / (1000 * 1000);
				dnsResTimeMilliSec = (uint32_t) (eTime - sTime);
			}
		}
	}

	switch(pDnsSession->ipVer)
	{
		case IPVersion4:
						sessionKey = to_string(pDnsSession->dnsSessionV4Key);
						/* Change Source and Destination IP Long to dotted IP */
						long2Ip(pDnsSession->sIpv4, pDnsSession->sIpv6);
						long2Ip(pDnsSession->dIpv4, pDnsSession->dIpv6);
						break;

		case IPVersion6:
						sessionKey = pDnsSession->dnsSessionV6Key;
						/* Change Source and Destination IP Long to dotted IP */
						break;
	}

	if(strlen(pDnsSession->URL) == 0)
		strcpy(pDnsSession->URL, "NA");

	if(strstr(pDnsSession->errorDesc, "No Error") != NULL)
		pDnsSession->errorCode = 0;

	sprintf(csvXDR, "%d,%d,17,DNS,"			// 1- Probe Id			2- XDR Id		3- UDP				4-  DNS
					"%s,%s,%d,%s,%d,"		// 5- User Id			6- Source Ip	7- Source Port		8-  Dest Ip		9- Dest Port
					"%s,%d,%s,"				// 10- URL				11- Error Code	12- Error Desc
					"%s,"					// 13- Address
					"%lu,%lu,%u,"		    // 14- Start time		15- End Time	16- Resolve Time
					"%d,%s",		        // 17- Flush Type   	18- Key
					Global::PROBE_ID, DNS_XDR_ID,
					pDnsSession->sIpv6, pDnsSession->sIpv6, pDnsSession->sourcePort, pDnsSession->dIpv6, pDnsSession->destPort,
					pDnsSession->URL, pDnsSession->errorCode, pDnsSession->errorDesc,
					pDnsSession->resolvedIp,
					pDnsSession->queryStartEpochNanoSec, pDnsSession->queryEndEpochNanoSec, dnsResTimeMilliSec,
					pDnsSession->flushType, sessionKey.c_str());
}

string flusherUtility::getResolvedIp4(uint32_t dIp)
{
	lockDnsMap();
	std::string URL = findDns(dIp);
	unLockDnsMap();

	if(!URL.length())
		return("NULL");
	else
		return(URL);
}

string flusherUtility::findDns(uint32_t dIp)
{ return(getURLLookUp(dIp, DNSGlobal::dnsLookUpMap[dIp % 10])); }

string flusherUtility::getURLLookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap)
{
	std::map<uint32_t, std::string>::iterator itSp = dnsMap.find(ip);

	if(itSp != dnsMap.end())
		return(itSp->second);

	return "";
}

void flusherUtility::formateIPv6(char *buffer)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int domain = AF_INET6, ret;


	ret = inet_pton(domain, buffer, buf);
	if (ret <= 0)
	{
		if (ret == 0) {
			fprintf(stderr, "Not in presentation format");
		}
		else
			perror("inet_pton");
	}

	if (inet_ntop(domain, buf, buffer, INET6_ADDRSTRLEN) == NULL) {
	               perror("inet_ntop");
	}
}
