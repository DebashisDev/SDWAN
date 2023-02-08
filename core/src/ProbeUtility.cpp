/*
 * ProbeUtility.cpp
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <math.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ProbeUtility.h"

ProbeUtility::ProbeUtility()
{
	this->_name = "ProbeStatsLog";
	this->setLogLevel(Log::theLog().level());
}

ProbeUtility::~ProbeUtility()
{ }

uint32_t ProbeUtility::HextoDigits(char *hexadecimal)
{
	uint32_t decimalNumber = 0;
	char hexDigits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int i, j, power=0, digit;

	for(i=strlen(hexadecimal)-1; i >= 0; i--)
	{
		for(j=0; j<16; j++)
		{
			if(hexadecimal[i] == hexDigits[j])
				decimalNumber += j*pow(16, power);
		}
		 power++;
	}
	return decimalNumber;
}

uint32_t ProbeUtility::getLength(const BYTE packet, size_t offset)
{
	char hexadecimal[10];
	hexadecimal[0] = 0;

	sprintf(hexadecimal, "%02x%02x%02x", packet[offset], packet[offset+1], packet[offset+2]);

	uint32_t decimalNumber = 0;
	char hexDigits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int i, j, power=0, digit;

	for(i=strlen(hexadecimal)-1; i >= 0; i--)
	{
		for(j=0; j<16; j++)
		{
			if(hexadecimal[i] == hexDigits[j])
			{
				decimalNumber += j*pow(16, power);
			}
		}
		 power++;
	}
	return decimalNumber;
}

void ProbeUtility::Append(char *original, const char *add)
{
   while(*original)
      original++;

   while((*original++ = *add++))
   *original = 0;
}

uint16_t ProbeUtility::parseTcpTimeStamp(struct tcphdr *tcp, ULONG *tsval, ULONG *tsecr)
{
	char *tcpHeader;
	uint32_t op, opLen, len;

	if (!tsval || !tsecr)
		return 0;

	tcpHeader = ((char *)tcp) + sizeof(*tcp);
	len = 4 * tcp->doff - sizeof(*tcp);

	while (len > 0 && *tcpHeader != TCPOPT_EOL)
	{
		op = *tcpHeader++;

		if (op == TCPOPT_EOL)
			break;

		if (op == TCPOPT_NOP)
		{
			len--;
			continue;
		}

		opLen = *tcpHeader++;

		if (opLen < 2)
			break;

		if (opLen > len)
			break; /* not enough space */

		if (op == TCPOPT_TIMESTAMP && opLen == 10)
		{
			/* legitimate timestamp option */
			if (tsval)
			{
				memcpy((char *)tsval, tcpHeader, 4);
				*tsval = (uint32_t)ntohl(*tsval);
			}

			tcpHeader += 4;

			if (tsecr)
			{
				memcpy((char *)tsecr, tcpHeader, 4);
				*tsecr = (uint32_t)ntohl(*tsecr);
			}
			return 1;
		}

		len -= opLen;
		tcpHeader += opLen - 2;
	}
	*tsval = 0;
	*tsecr = 0;
	return 0;
}

void ProbeUtility::getIPHex(char *address, char *hexaddress)
{
	char *p, a[25];
	uint32_t i = 0;

	p = NULL;
	a[0] = 0;
	p = (char *)strtok((char *)address, ".");

	while(p!= NULL)
	{
		sprintf((char *)a, "%02x", atoi((const char *)p));
	    strcat((char *)hexaddress, (const char *)a);
	    a[0] = 0;

	    if(i < 3)
	      strcat((char *)hexaddress, ".");
	    p = (char *)strtok(NULL, ".");
	    i++;
	}
}

void ProbeUtility::fillIP(char *address, char *fillInAddress)
{
	char *p, a[25];
	uint32_t i = 0;

	p = NULL;
	a[0] = 0;
	p = (char *)strtok((char *)address, ".");

	while(p!= NULL)
	{
		sprintf((char *)a, "%03d", atoi((const char *)p));
	    strcat((char *)fillInAddress, (const char *)a);
	    a[0] = 0;

	    if(i < 3)
	      strcat((char *)fillInAddress, ".");
	    p = (char *)strtok(NULL, ".");
	    i++;
	}
}


void ProbeUtility::ExtractIP4Address(const BYTE packet, char *ipBuffer, uint32_t loc)
{
	unsigned int address;

	address = (packet[loc] << 24) | (packet[loc+1] << 16) | (packet[loc+2] << 8) | (packet[loc+3]);
	sprintf((char *)ipBuffer,"%d.%d.%d.%d",(address & 0xFF000000) >> 24,(address & 0x00FF0000) >> 16,(address & 0x0000FF00) >> 8, address & 0x000000FF);
}

//void ProbeUtility::ExtractIP6Address(const BYTE packet, char *ipBuffer, uint32_t loc)
//{
//	unsigned char buf[sizeof(struct in6_addr)];
//	int domain = AF_INET6, ret;
//
//	ipBuffer[0] = 0;
//	ret = 0;
//
//	sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[loc], packet[loc+1], \
//			packet[loc+2], packet[loc+3], packet[loc+4], packet[loc+5], packet[loc+6], packet[loc+7], packet[loc+8], packet[loc+9], \
//			packet[loc+10], packet[loc+11], packet[loc+12], packet[loc+13], packet[loc+14], packet[loc+15], packet[loc+16]);
//
//	ret = inet_pton(domain, ipBuffer, buf);
//	if (ret <= 0)
//	{
//		if (ret == 0) {
//			fprintf(stderr, "Not in presentation format");
//			ipBuffer[0] = 0;
//		}
//		else
//			perror("inet_pton");
//	}
//
//	if (inet_ntop(domain, buf, ipBuffer, INET6_ADDRSTRLEN) == NULL) {
//				   perror("inet_ntop");
//				   ipBuffer[0] = 0;
//	}
//}


void ProbeUtility::ExtractIP6Prefix(const BYTE packet, char *ipBuffer, uint32_t start, uint32_t end)
{
	ipBuffer[0] = 0;

	switch(end)
	{
		/*
		 * IPv6 Address with prefix length : 2001:db8:abcd:0012::0/64
		 * Range :: 2001:0DB8:ABCD:0012:0000:0000:0000:0000 ~ 2001:0DB8:ABCD:0012:FFFF:FFFF:FFFF:FFFF
		 */
		case 8:
			sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					packet[start], packet[start+1], packet[start+2], packet[start+3],
					packet[start+4], packet[start+5], packet[start+6], packet[start+7]);
			break;

		/*
		 * IPv6 Address with prefix length : 2001:db8:abcd:0012::0/80
		 * Range :: 2001:0DB8:ABCD:0012:0000:0000:0000:0000 ~ 2001:0DB8:ABCD:0012:0000:FFFF:FFFF:FFFF
		 */

		case 10:
			sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					packet[start], packet[start+1], packet[start+2], packet[start+3],
					packet[start+4], packet[start+5], packet[start+6], packet[start+7],
					packet[start+8], packet[start+9]);
			break;

		/*
		 * IPv6 Address with prefix length : 2001:db8:abcd:0012::0/96
		 * Range :: 2001:0DB8:ABCD:0012:0000:0000:0000:0000 ~ 2001:0DB8:ABCD:0012:0000:0000:FFFF:FFFF
		 */

		case 12:
			sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					packet[start], packet[start+1], packet[start+2], packet[start+3],
					packet[start+4], packet[start+5], packet[start+6], packet[start+7],
					packet[start+8], packet[start+9], packet[start+10], packet[start+11]);
			break;

		/*
		 * IPv6 Address with prefix length : 2001:db8:abcd:0012::0/112
		 * Range :: 2001:0DB8:ABCD:0012:0000:0000:0000:0000 ~ 2001:0DB8:ABCD:0012:0000:0000:0000:FFFF
		 */

		case 14:
			sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					packet[start], packet[start+1], packet[start+2], packet[start+3],
					packet[start+4], packet[start+5], packet[start+6], packet[start+7],
					packet[start+8], packet[start+9], packet[start+10], packet[start+11],
					packet[start+12], packet[start+13]);
			break;

		/*
		 * IPv6 Address with prefix length : 2001:db8:abcd:0012::0/128
		 * Range :: 2001:0DB8:ABCD:0012:0000:0000:0000:0000 ~ 2001:0DB8:ABCD:0012:0000:0000:0000:0000
		 */

		case 16:
			sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					packet[start], packet[start+1], packet[start+2], packet[start+3],
					packet[start+4], packet[start+5], packet[start+6], packet[start+7],
					packet[start+8], packet[start+9], packet[start+10], packet[start+11],
					packet[start+12], packet[start+13], packet[start+14], packet[start+15]);
			break;

		default:
			return;
	}
}

void ProbeUtility::pinThread(pthread_t th, uint16_t core_num)
{
	   cpu_set_t cpuset;

           /* Set affinity mask to include CPUs 0 to 7 */

           CPU_ZERO(&cpuset);
           CPU_SET(core_num,&cpuset);

           int s = pthread_setaffinity_np(th, sizeof(cpu_set_t), &cpuset);
           if (s != 0)
               handle_error_en(s, "pthread_setaffinity_np");

           /* Check the actual affinity mask assigned to the thread */

           s = pthread_getaffinity_np(th, sizeof(cpu_set_t), &cpuset);
           if (s != 0)
               handle_error_en(s, "pthread_getaffinity_np");

           printf("Set returned by pthread_getaffinity_np() contained:\n");
           if (CPU_ISSET(core_num, &cpuset))
               printf("    CPU %d\n", core_num);

}

vector<string> ProbeUtility::split(string str, char delimiter)
{
	vector<string> internal;
	stringstream ss(str);
	string token;

	while(getline(ss, token, delimiter)) {
	    internal.push_back(token);
	}
	return internal;
}

uint8_t ProbeUtility::matchIPs(uint32_t src, uint32_t dst, uint32_t net, uint32_t num_bits)
{
	return(matchIP(src, net, num_bits) || matchIP(dst, net, num_bits));
}

uint8_t ProbeUtility::matchIP(uint32_t ip_to_check, uint32_t net, uint32_t num_bits)
{
  uint32_t mask = 0;
  mask = ~(~mask >> num_bits);
  return(((ip_to_check & mask) == (net & mask)) ? true : false);
}

void ProbeUtility::HEXDUMP(const void* pv, int len)
{
	const unsigned char* p = (const unsigned char*) pv;
	int i;
	for( i = 0; i < len; ++i ) {
		const char* eos;
			switch( i & 15 ) {
				case 0:
					printf("%08x  ", i);
					eos = "";
					break;
				case 1:
					eos = " ";
					break;
				case 15:
					eos = "\n";
					break;
				default:
					eos = (i & 1) ? " " : "";
					break;
			}
			printf("%02x%s", (unsigned) p[i], eos);
	}
	printf(((len & 15) == 0) ? "\n" : "\n\n");
}

uint64_t ProbeUtility::getIpv4SessionKey(uint8_t &protocol, uint8_t direction, uint32_t &sourceIp, uint32_t &destIp, uint16_t &sourcePort, uint16_t &destPort)
{
	uint64_t sessionKey = 0;

	switch(direction)
	{
		case UP:
				sessionKey = (sourceIp*59)^(destIp)^(sourcePort << 16)^(destPort)^(protocol);
				break;

		case DOWN:
				sessionKey = (destIp*59)^(sourceIp)^(destPort << 16)^(sourcePort)^(protocol);
				break;

		default:
			sessionKey = (sourceIp*59)^(destIp)^(sourcePort << 16)^(destPort)^(protocol);
			break;
	}
	return sessionKey;
}

void ProbeUtility::dnsDumpIpv4Data(string dir)
{
	char fileName[50], finalFileName[50];
	fileName[0] = 0;
	finalFileName[0] = 0;
	uint32_t recordCount = 0;

	/* Dumping File Hourly */
	sprintf(fileName, "%s.csv.in", "dnsIpv4data");
	string filePath = dir + string(fileName);

	ofstream fileHandler;

	fileHandler.open(filePath.c_str(), ios :: out);

	if(fileHandler.fail())
	{
		printf(" Error in Dumping Daily IPv4 DNS Lookup Store File : %s\n", filePath.c_str());
		TheLog_nc_v1(Log::Info, name()," Error in dumping Ipv4 DNS data to file [%s]", filePath.c_str());
	}
	else
	{
		for(uint16_t i = 0; i < 10; i ++)
		{
			for(auto elem : DNSGlobal::dnsLookUpMap[i])
			{
				recordCount++;
				fileHandler << elem.first << "," << elem.second << endl;
			}
		}

		fileHandler.close();
		printf(" Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.\n", recordCount, filePath.c_str());
		TheLog_nc_v2(Log::Info, name()," Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.", recordCount, filePath.c_str());

		sprintf(finalFileName, "%s.csv", "dnsIpv4data");
		string filePath1 = dir + string(finalFileName);

		rename(filePath.c_str(), filePath1.c_str());

		recordCount = 0;
		filePath.clear();
		filePath1.clear();
	}
}

void ProbeUtility::loadResolvedIpv4(string dir)
{
	char fileName[50];
	sprintf(fileName, "%s.csv", "dnsIpv4data");
	string filePath = dir + string(fileName);

	std::string line;
	std::string url;
	uint32_t ip;
	uint32_t loadedCnt = 0;
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
	TheLog_nc_v2(Log::Info, name(),"     Loaded [01] [ %06u ] Records in Dns IPv4 Lookup Map from file [%s]", loadedCnt, filePath.c_str());
	printf("     Loaded [ %06u ] Records in Dns IPv4 Lookup Map from file [%s].\n", loadedCnt, filePath.c_str());
}
