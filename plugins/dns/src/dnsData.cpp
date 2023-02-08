/*
 * DnsData.cpp
 *
 *  Created on: 11-Jun-2016
 *      Author: debashis
 */

#include "dnsData.h"

using namespace std;

dnsData::dnsData()
{
	this->_name = "dnsData";
	this->setLogLevel(Log::theLog().level());
}

dnsData::~dnsData()
{}


void dnsData::updateUrl(uint32_t ip, std::string url)
{
	uint16_t idx = ip % 10;
	DNSGlobal::dnsLookUpMap[idx][ip] = std::string(url);
}

string dnsData::lookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap)
{
	std::map<uint32_t, std::string>::iterator itSp = dnsMap.find(ip);

	if(itSp != dnsMap.end())
		return(itSp->second);

	return "NA";
}

void dnsData::getUrl(std::string& url, uint32_t ip)
{
	uint16_t idx = ip % 10;
	url = lookUp(ip, DNSGlobal::dnsLookUpMap[idx]);
}

//void dnsData::updateV6Url(string resolvedip, string url)
//{ DNSGlobal::dnsV6LookUpMap[string(resolvedip)] = std::string(url); }
//
//void dnsData::getDNSV6UrlForIP(std::string& url, char *ip)
//{
//	std::map<std::string, std::string>::iterator itSp1 = DNSGlobal::dnsV6LookUpMap.find(std::string(ip));
//
//	if( itSp1 != DNSGlobal::dnsV6LookUpMap.end())
//	{
//		url = itSp1->second;
//		return;
//	}
//}

string dnsData::getDNSKey(uint32_t destAddrLong, uint32_t sourceAddrLong)
{
	char dnsKey[25];
	sprintf(dnsKey,"%010u-%010u", destAddrLong, sourceAddrLong);
	return std::string(dnsKey);
}
