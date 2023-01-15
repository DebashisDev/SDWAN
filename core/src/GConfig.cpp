/*
 * GConfig.cpp
 *
 *  Created on: 26-Jul-2016
 *      Author: Debashis
 */

#include "GConfig.h"
#include "IPGlobal.h"

GConfig::GConfig()
{}

GConfig::~GConfig()
{ }

void GConfig::initialize(char *fileName)
{
	printf("\n Loading Configurations...\n");
	openConfigFile(fileName);

	while(!fp.eof())
	{
		Key.clear();
		fp >> Key;

		/* Log Setting */
		get_probeId(Key);								/* PROBE_ID */
		get_logLevel(Key);								/* LOG_LEVEL */
		get_printStats(Key);							/* PRINT_STATS */
		get_printStatsFrequency(Key);					/* PRINT_STATS_FREQ_SEC */
		get_logStatsFrequency(Key);						/* LOG_STATS_FREQ_SEC */

		/* Log & XDR path Setting */
		get_xdrDir(Key);								/* XDR_DIR */
		get_logDir(Key);								/* LOG_DIR */
		get_dataDir(Key);								/* DATA_DIR */
		get_unKnownXdrDir(Key);							/* UNKNOWN_XDR_DIR */

		/* Admin Setting */
		get_adminFlag(Key);								/* ADMIN_FLAG */
		get_adminPort(Key);								/* ADMIN_PORT */

		/* Network Interface Setting */
		get_ethernetInterface(Key);						/* ETHERNET_INTERFACE */
		get_solarInterface(Key);						/* SOLAR_INTERFACE */
		get_solarTimeStamp(Key);						/* SOLARFLARE_HW_TIMESTAMP */
		get_interfaceCPU(Key);							/* PKT_LISTENER_CPU_CORE */

		/* Network packet Setting */
		get_packetLen(Key);								/* MAX_PKT_LEN_PER_INTERFACE */
		get_PPSPerInterface(Key);						/* PPS_PER_INTERFACE */
		get_PPSCap(Key);								/* PPS_CAP_PERCENTAGE */

		/* Router / Interface Setting */
		get_routerPerInterface(Key);					/* ROUTER_PER_INTERFACE */
		get_routerCPU(Key);								/* PKT_ROUTER_CPU_CORE */

		/* Range Setting */
		get_IPV4Range(Key);								/* IPV4 RANGE */
		get_ipv6Range(Key);								/* IPV6 RANGE */
		get_ipv6ProcessingFlag(Key);					/* IPV6_PROCESSING */
		get_ProcessOutOfRange(Key);						/* PROCESS_OUT_OF_RANGE_IP */

		/* CDB Bandwidth Setting */
		get_ProcessCDN(Key);							/* CDN PROCESSING */

		if(Global::PROCESS_CDN)
		{
			get_CdnIPRangeV4(Key);						/* CDN IPV4 RANGE */
			get_CdnIPRangeV6(Key);						/* CDN IPV6 RANGE */
		}

		/* TCP Setting */
		get_userAgentFlag(Key);							/* PROCESS_USER_AGENT */
		get_maxTcpSize(Key);							/* MAX_TCP_SIZE */

		/* DNS Setting */
		get_DnsAnswerCount(Key);						/* DNS_ANSWER */

		/* TCP Session Manager Setting */
		get_noOfTcpSmInstance(Key);						/* TCP_SESSION_MANAGER_INSTANCES */
		get_tcpSmCpu(Key);								/* TCP_SESSION_MANAGER_CPU_CORE */
		get_smTimeLimit(Key);							/* SESSION_TIME_LIMIT */
		get_smPacketLimit(Key);							/* SESSION_PKT_LIMIT */
		get_ipSmCleanUpTime(Key);						/* IP_SESSION_CLEAN_UP_TIMEOUT_SEC */
		get_vpsPacketPerSec(Key);						/* VPS_PACKET_PER_SEC */
		get_checkDuplicateFlag(Key);					/* CHECK_DUPLICATE */
		get_processAckFlag(Key);						/* PROCESS_ACK */
		get_ackCrateFlag(Key);							/* ACK_CREATE_SESSION */
		get_noOfTcpFlusher(Key);						/* NO_OF_TCP_FLUSHER */
		get_tcpFlushCPU(Key);							/* TCP_FLUSHER_CPU_CORE */
		get_ipWriteXdrFlag(Key);						/* IP_WRITE_XDR */

		/* UDP Session Manager Setting */
		get_noOfUdpSmInstance(Key);						/* UDP_SESSION_MANAGER_INSTANCES */
		get_udpSmCpu(Key);								/* TCP_SESSION_MANAGER_CPU_CORE */
		get_udpXdrForDns(Key);							/* UDP_XDR_FOR_DNS */
		get_noOfUdpFlusher(Key);						/* NO_OF_UDP_FLUSHER */
		get_udpFlushCPU(Key);							/* UDP_FLUSHER_CPU_CORE */

		/* DNS Session Manager Setting */
		get_noOfDnsSmInstance(Key);						/* DNS_SESSION_MANAGER_INSTANCES */
		get_dnsSmCpu(Key);								/* DNS_SESSION_MANAGER_CPU_CORE */
		get_dnsSmCleanUpTime(Key);						/* DNS_SESSION_CLEAN_UP_TIMEOUT_SEC */
		get_noOfDnsFlusher(Key);						/* NO_OF_DNS_FLUSHER */
		get_dnsFlushCPU(Key);							/* DNS_FLUSHER_CPU_CORE */
		get_dnsWriteXdrFlag(Key);						/* DNS_WRITE_XDR */

		/* UNMAPPED Session Manager Setting */
		get_noOfUnmSmInstance(Key);						/* UNM_SESSION_MANAGER_INSTANCES */
		get_unmSmCpu(Key);								/* UNM_SESSION_MANAGER_CPU_CORE */
		get_noOfUnmFlusher(Key);						/* NO_OF_UNM_FLUSHER */
		get_unmFlushCPU(Key);							/* UNMAPPED_FLUSHER_CPU_CORE */
		get_unmWriteXdrFlag(Key);						/* UIP_WRITE_XDR */
	}
	closeConfigFile();
}

/* Log Setting */

void GConfig::get_probeId(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROBE_ID") == 0)
	{
		fp >> Value;
		Global::PROBE_ID = atol(Value.c_str());
		printf("%50s\t%50d\n", "PROBE_ID", Global::PROBE_ID);
	}
}

void GConfig::get_logLevel(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_LEVEL") == 0)
	{
		fp >> Value;
		Global::LOG_LEVEL = atoi(Value.c_str());
		printf("%50s\t%50d\n", "LOG_LEVEL", Global::LOG_LEVEL);
	}
}

void GConfig::get_printStats(std::string& Key)
{
	Value.clear();

	if(Key.compare("PRINT_STATS") == 0)
	{
		fp >> Value;
		Global::PRINT_STATS = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "PRINT_STATS", Value.c_str());

	}
}

void GConfig::get_printStatsFrequency(std::string& Key)
{
	Value.clear();

	if(Key.compare("PRINT_STATS_FREQ_SEC") == 0)
	{
		fp >> Value;
		Global::PRINT_STATS_FREQ_SEC = atoi(Value.c_str());
		printf("%50s\t%50d\n", "PRINT_STATS_FREQ_SEC", Global::PRINT_STATS_FREQ_SEC);
	}
}

void GConfig::get_logStatsFrequency(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_STATS_FREQ_SEC") == 0)
	{
		fp >> Value;
		Global::LOG_STATS_FREQ_SEC = atoi(Value.c_str());
		printf("%50s\t%50d\n", "LOG_STATS_FREQ_SEC", Global::LOG_STATS_FREQ_SEC);
	}
}

/* Log & XDR path Setting */

void GConfig::get_xdrDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("XDR_DIR") == 0)
	{
		fp >> Value;
		Global::XDR_DIR = Value;
		printf("%50s\t%50s\n", "XDR_DIR", Global::XDR_DIR.c_str());
	}
}

void GConfig::get_logDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_DIR") == 0)
	{
		fp >> Value;
		Global::LOG_DIR = Value;
		printf("%50s\t%50s\n", "LOG_DIR", Global::LOG_DIR.c_str());
	}
}

void GConfig::get_dataDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("DATA_DIR") == 0)
	{
		fp >> Value;
		Global::DATA_DIR = Value;
		printf("%50s\t%50s\n", "DATA_DIR", Global::DATA_DIR.c_str());
	}
}

void GConfig::get_unKnownXdrDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("UNKNOWN_XDR_DIR") == 0)
	{
		fp >> Value;
		Global::UNKNOWN_XDR_DIR = Value;
		printf("%50s\t%50s\n", "UNKNOWN_XDR_DIR", Global::UNKNOWN_XDR_DIR.c_str());
	}
}

/* Admin Setting */

void GConfig::get_adminFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("ADMIN_FLAG") == 0)
	{
		fp >> Value;
		Global::ADMIN_FLAG = Value.compare("true") == 0 ? 1 : 0;
		printf("%50s\t%50s\n", "ADMIN_FLAG", Value.c_str());
	}
}

void GConfig::get_adminPort(std::string& Key)
{
	Value.clear();

	if(Key.compare("ADMIN_PORT") == 0)
	{
			fp >> Value;
			Global::ADMIN_PORT = Value;
			printf("%50s\t%50s\n", "ADMIN_PORT", Global::ADMIN_PORT.c_str());
	}
}

/* Network Interface Setting */

void GConfig::get_ethernetInterface(std::string& Key)
{
	Value.clear();
	buffer[0] = 0;

	if(Key.compare("ETHERNET_INTERFACE") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			Global::ETHERNET_INTERFACES[cnt] = std::string(pch);
			pch = strtok (NULL, ",");
			buffer[0] = 0;
			sprintf(buffer, "ETHERNET_INTERFACES[%d]", cnt);
			printf("%50s\t%50s\n", buffer, Global::ETHERNET_INTERFACES[cnt].c_str());
			cnt++;
		}
		Global::NO_OF_NIC_INTERFACE = cnt;
		printf("%50s\t%50d\n", "ETHERNET_INTERFACE No.", Global::NO_OF_NIC_INTERFACE);
	}
}

void GConfig::get_solarInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("SOLAR_INTERFACE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			Global::SOLAR_INTERFACES[cnt] = std::string(pch);
			pch = strtok (NULL, ",");
			buffer[0] = 0;
			sprintf(buffer, "SOLAR_INTERFACES[%d]", cnt);
			printf("%50s\t%50s\n", buffer, Global::SOLAR_INTERFACES[cnt].c_str());
			cnt++;
		}
		Global::NO_OF_SOLAR_INTERFACE = cnt;
		printf("%50s\t%50d\n", "SOLAR_INTERFACES No.", Global::NO_OF_SOLAR_INTERFACE);
	}
}

void GConfig::get_solarTimeStamp(std::string& Key)
{
	Value.clear();

	if(Key.compare("SOLARFLARE_HW_TIMESTAMP") == 0)
	{
		fp >> Value;
		Global::SOLARFLARE_HW_TIMESTAMP = Value.compare("true") == 0 ? 1 : 0;
		printf("%50s\t%50s\n", "SOLARFLARE_HW_TIMESTAMP",  Value.c_str());
	}
}

void GConfig::get_interfaceCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("PKT_LISTENER_CPU_CORE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			Global::PKT_LISTENER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "PKT_LISTENER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::PKT_LISTENER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

/* Network packet Setting */

void GConfig::get_packetLen(std::string& Key)
{
	Value.clear();

	if(Key.compare("MAX_PKT_LEN_PER_INTERFACE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			Global::MAX_PKT_LEN_PER_INTERFACE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "MAX_PKT_LEN_PER_INTERFACE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::MAX_PKT_LEN_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_PPSPerInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("PPS_PER_INTERFACE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			Global::PPS_PER_INTERFACE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "PPS_PER_INTERFACE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::PPS_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_PPSCap(std::string& Key)
{
	Value.clear();

	if(Key.compare("PPS_CAP_PERCENTAGE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			Global::PPS_CAP_PERCENTAGE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "PPS_CAP_PERCENTAGE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::PPS_CAP_PERCENTAGE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

/* Range Setting */

//void GConfig::get_IPV4Range(std::string& Key)
//{
//	Value.clear();
//
//	if(Key.compare("IPV4_RANGE") == 0)
//	{
//		fp >> Value;
//		char *pchHash, *pchComma;
//		uint16_t cnt, cnt1;
//		uint32_t x = 0;
//		cnt = cnt1 = 0;
//		size_t pos = 0;
//		std::string token;
//
//		while ((pos = Value.find(",")) != std::string::npos) {
//			token = Value.substr(0, pos);
//			pchHash = strtok((char *)token.c_str(),"-");
//			while (pchHash != NULL)
//			{
//				Global::IPV4_RANGE[cnt1][cnt] = ipToLong(pchHash, &x);
//				buffer[0] = 0;
//				sprintf(buffer, "%s[%d][%d]", "IPV4_RANGE", cnt1, cnt);
//				printf("%50s\t%50lu\n", buffer, Global::IPV4_RANGE[cnt1][cnt]);
//				pchHash = strtok (NULL, "-");
//				cnt++;
//				x = 0;
//			}
//			cnt1++;
//			cnt = 0;
//			Value.erase(0, pos + 1);
//		}
//		cnt = 0;
//		x = 0;
//		pchComma = strtok((char *)Value.c_str(),"-");
//		while (pchComma != NULL)
//		{
//			Global::IPV4_RANGE[cnt1][cnt] = ipToLong(pchComma, &x);
//			sprintf(buffer, "%s[%d][%d]", "IPV4_RANGE", cnt1, cnt);
//			printf("%50s\t%50lu\n", buffer, Global::IPV4_RANGE[cnt1][cnt]);
//			pchComma = strtok (NULL, "-");
//			cnt++;
//			x = 0;
//		}
//		Global::IPV4_NO_OF_RANGE = cnt1;
//	}
//}

void GConfig::get_IPV4Range(std::string& Key)
{
	char startIp[16], endIp[16];
	uint32_t x = 0;

	Value.clear();

	if(Key.compare("IPV4_RANGE") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			Global::IPV4_RANGE[cnt][0] = ipToLong(startIp, &x);
			Global::IPV4_RANGE[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		Global::IPV4_NO_OF_RANGE = cnt;
		printf("\tIPV4_NO_OF_RANGE			:: %02d\n", Global::IPV4_NO_OF_RANGE);

		for(uint16_t i = 0; i < Global::IPV4_NO_OF_RANGE; i++)
		printf("\tIPV4_RANGE        			:: [%u]| [%u]\n", Global::IPV4_RANGE[i][0], Global::IPV4_RANGE[i][1]);
	}
}

void GConfig::get_ipv6Range(std::string& Key)
{
	int i = 0;

	Value.clear();

	if(Key.compare("IPV6_RANGE") == 0)
	{
		fp >> Value;
		i = 0;
		char * pch;
		pch = strtok((char *)Value.c_str(),",");
		while (pch != NULL)
		{
			Global::IPV6Range.push_back(pch);

			printf("%50s\t%50s\n", "IPV6_RANGE",  pch);
			pch = strtok (NULL, ",");
			i++;
		}
	}
}

void GConfig::converSubNetToRange(char *ipr, char *Start, char *End)
{
	string str1 = "";
	string str2 = "";

	int idx = 0;
	int len = strlen(ipr) - 3;

	while(len--)
	{
		str1 += ipr[idx];
		idx++;
	}

	strcpy(Start, str1.c_str());

	idx++;
	str2 += ipr[idx];
	idx++;
	str2 += ipr[idx];

	strcpy(End, initSection::ipSubNetMap[atoi(str2.c_str())].c_str());
}
void GConfig::get_ipv6ProcessingFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("IPV6_PROCESSING") == 0)
	{
		fp >> Value;
		Global::IPV6_PROCESSING = Value.compare("true") == 0 ? 1 : 0;
		printf("%50s\t%50s\n", "IPV6_PROCESSING",  Value.c_str());
	}
}

void GConfig::get_ProcessOutOfRange(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_OUT_OF_RANGE_IP") == 0)
	{
		fp >> Value;
		Global::PROCESS_OUT_OF_RANGE_IP = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "PROCESS_OUT_OF_RANGE_IP", Value.c_str());
	}
}

/* Router / Interface Setting */

void GConfig::get_routerPerInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("ROUTER_PER_INTERFACE") == 0)
	{
		fp >> Value;
		int cnt = 0;
		char *pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			Global::ROUTER_PER_INTERFACE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "ROUTER_PER_INTERFACE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::ROUTER_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_routerCPU(std::string& Key)
{
	if(Key.compare("PKT_ROUTER_CPU_CORE") == 0)
	{
		fp >> Value;
		char *pchHash, *pchComma;
		int cnt, cnt1;

		cnt = cnt1 = 0;
		size_t pos = 0;
		std::string token;

		while ((pos = Value.find("-")) != std::string::npos)
		{
		    token = Value.substr(0, pos);
		    pchHash = strtok((char *)token.c_str(),",");

		    while (pchHash != NULL)
			{
				Global::PKT_ROUTER_CPU_CORE[cnt1][cnt] = atoi(pchHash);
				buffer[0] = 0;
				sprintf(buffer, "%s[%d][%d]", "PKT_ROUTER_CPU_CORE", cnt1, cnt);
				printf("%50s\t%50d\n", buffer, Global::PKT_ROUTER_CPU_CORE[cnt1][cnt]);
				pchHash = strtok (NULL, ",");
				cnt++;
			}
			cnt1++;
			cnt = 0;
		    Value.erase(0, pos + 1);
		}
		cnt = 0;
		pchComma = strtok((char *)Value.c_str(),",");

		while (pchComma != NULL)
		{
			Global::PKT_ROUTER_CPU_CORE[cnt1][cnt] = atoi(pchComma);
			buffer[0] = 0;
			sprintf(buffer, "%s[%d][%d]", "PKT_ROUTER_CPU_CORE", cnt1, cnt);
			printf("%50s\t%50d\n", buffer, Global::PKT_ROUTER_CPU_CORE[cnt1][cnt]);

			pchComma = strtok (NULL, ",");
			cnt++;
		}
	}
}

/* CDB Bandwidth Setting */

void GConfig::get_ProcessCDN(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_CDN") == 0)
	{
		fp >> Value;
		Global::PROCESS_CDN = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "PROCESS_CDN", Value.c_str());
	}
}

void GConfig::get_CdnIPRangeV4(std::string& Key)
{
	Value.clear();

	if(Key.compare("CDN_IPV4_RANGE") == 0)
	{
		fp >> Value;
		char *pchHash, *pchComma;
		uint32_t x = 0;
		uint16_t cnt = 0, cnt1 = 0;
		size_t pos = 0;
		std::string token;

		while ((pos = Value.find(",")) != std::string::npos) {
			token = Value.substr(0, pos);
			pchHash = strtok((char *)token.c_str(),"-");
			while (pchHash != NULL)
			{
				Global::CDN_IPV4_RANGE[cnt1][cnt] = ipToLong(pchHash, &x);
				buffer[0] = 0;
				sprintf(buffer, "%s[%d][%d]", "CDN_IPV4_RANGE", cnt1, cnt);
				printf("%50s\t%50lu\n", buffer, Global::CDN_IPV4_RANGE[cnt1][cnt]);
				pchHash = strtok (NULL, "-");
				cnt++;
				x = 0;
			}
			cnt1++;
			cnt = 0;
			Value.erase(0, pos + 1);
		}
		cnt = 0;
		x = 0;
		pchComma = strtok((char *)Value.c_str(),"-");
		while (pchComma != NULL)
		{
			Global::CDN_IPV4_RANGE[cnt1][cnt] = ipToLong(pchComma, &x);
			sprintf(buffer, "%s[%d][%d]", "CDN_IPV4_RANGE", cnt1, cnt);
			printf("%50s\t%50lu\n", buffer, Global::CDN_IPV4_RANGE[cnt1][cnt]);
			pchComma = strtok (NULL, "-");
			cnt++;
			x = 0;
		}
		Global::NO_OF_IPV4_CDN = cnt1;
	}
}

void GConfig::get_CdnIPRangeV6(std::string& Key)
{
	Value.clear();

	if(Key.compare("CDN_IPV6_RANGE") == 0)
	{
		fp >> Value;
		int i = 0;
		char * pch;
		pch = strtok((char *)Value.c_str(),",");
		while (pch != NULL)
		{
			Global::CDN_IPV6_RANGE.push_back(pch);

			printf("%50s\t%50s\n", "CDN_IPV6_RANGE", pch);
			pch = strtok (NULL, ",");
			i++;
		}
	}
}

/* TCP Setting */

void GConfig::get_userAgentFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_USER_AGENT") == 0)
	{
		fp >> Value;
		Global::PROCESS_USER_AGENT = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "PROCESS_USER_AGENT", Value.c_str());
	}
}

void GConfig::get_maxTcpSize(std::string& Key)
{
	Value.clear();

	if(Key.compare("MAX_TCP_SIZE") == 0)
	{
		fp >> Value;
		Global::MAX_TCP_SIZE = atoi(Value.c_str());
		printf("%50s\t%50d\n", "MAX_TCP_SIZE", Global::MAX_TCP_SIZE);
	}
}

/* DNS Setting */

void GConfig::get_DnsAnswerCount(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_ANSWER") == 0)
	{
		fp >> Value;
		Global::DNS_ANSWER = atoi(Value.c_str());
		printf("%50s\t%50d\n", "DNS_ANSWER", Global::DNS_ANSWER);
	}
}

/* TCP Session Manager Setting */

void GConfig::get_noOfTcpSmInstance(std::string& Key)
{
	Value.clear();

	if(Key.compare("TCP_SESSION_MANAGER_INSTANCES") == 0)
	{
		fp >> Value;
		Global::TCP_SESSION_MANAGER_INSTANCES = atoi(Value.c_str());

		if(Global::TCP_SESSION_MANAGER_INSTANCES > TCP_MAX_SESSION_MANAGER_SUPPORT)
		{
			printf("\n Max Number of Session Manager can be %02 \n", TCP_MAX_SESSION_MANAGER_SUPPORT);
			exit(1);
		}
		printf("%50s\t%50d\n", "TCP_SESSION_MANAGER_INSTANCES", Global::TCP_SESSION_MANAGER_INSTANCES);
	}
}

void GConfig::get_tcpSmCpu(std::string& Key)
{
	Value.clear();

	if(Key.compare("TCP_SESSION_MANAGER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::TCP_SESSION_MANAGER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "TCP_SESSION_MANAGER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::TCP_SESSION_MANAGER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_smTimeLimit(std::string& Key)
{
	Value.clear();

	if(Key.compare("SESSION_TIME_LIMIT") == 0)
	{
		fp >> Value;
		Global::SESSION_TIME_LIMIT = atoi(Value.c_str());
		printf("%50s\t%50d\n", "SESSION_TIME_LIMIT", Global::SESSION_TIME_LIMIT);
	}
}

void GConfig::get_smPacketLimit(std::string& Key)
{
	Value.clear();

	if(Key.compare("SESSION_PKT_LIMIT") == 0)
	{
		fp >> Value;
		Global::SESSION_PKT_LIMIT = atoi(Value.c_str());
		printf("%50s\t%50d\n", "SESSION_TIME_LIMIT", Global::SESSION_PKT_LIMIT);
	}
}

void GConfig::get_ipSmCleanUpTime(std::string& Key)
{
	Value.clear();

	if(Key.compare("IP_SESSION_CLEAN_UP_TIMEOUT_SEC") == 0)
	{
		fp >> Value;
		Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC = atoi(Value.c_str());
		printf("%50s\t%50d\n", "IP_SESSION_CLEAN_UP_TIMEOUT_SEC", Global::IP_SESSION_CLEAN_UP_TIMEOUT_SEC);
	}
}

void GConfig::get_vpsPacketPerSec(std::string& Key)
{
	Value.clear();

	if(Key.compare("VPS_PACKET_PER_SEC") == 0)
	{
		fp >> Value;
		Global::VPS_PACKET_PER_SEC = atoi(Value.c_str());
		printf("%50s\t%50d\n", "VPS_PACKET_PER_SEC", Global::VPS_PACKET_PER_SEC);
	}
}

void GConfig::get_checkDuplicateFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("CHECK_DUPLICATE") == 0)
	{
		fp >> Value;
		Global::CHECK_DUPLICATE = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "CHECK_DUPLICATE", Value.c_str());
	}
}

void GConfig::get_processAckFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_ACK") == 0)
	{
		fp >> Value;
		Global::PROCESS_ACK = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "PROCESS_ACK", Value.c_str());
	}
}

void GConfig::get_ackCrateFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("ACK_CREATE_SESSION") == 0)
	{
		fp >> Value;
		Global::ACK_CREATE_SESSION = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "ACK_CREATE_SESSION", Value.c_str());
	}
}

void GConfig::get_noOfTcpFlusher(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_TCP_FLUSHER") == 0)
	{
		fp >> Value;
		Global::NO_OF_TCP_FLUSHER = atoi(Value.c_str());
		printf("%50s\t%50s\n", "NO_OF_TCP_FLUSHER", Value.c_str());
	}
}

void GConfig::get_tcpFlushCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("TCP_FLUSHER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::TCP_FLUSHER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "IP_FLUSHER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::TCP_FLUSHER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_ipWriteXdrFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("IP_WRITE_XDR") == 0)
	{
		fp >> Value;
		if(Value.compare("true") == 0)
			Global::IP_WRITE_XDR = true;
		else
			Global::IP_WRITE_XDR = false;
		printf("%50s\t%50s\n", "IP_WRITE_XDR", Value.c_str());
	}
}

/* UDP Session Manager Setting */

void GConfig::get_noOfUdpSmInstance(std::string& Key)
{
	Value.clear();

	if(Key.compare("UDP_SESSION_MANAGER_INSTANCES") == 0)
	{
		fp >> Value;
		Global::UDP_SESSION_MANAGER_INSTANCES = atoi(Value.c_str());

		if(Global::UDP_SESSION_MANAGER_INSTANCES > UDP_MAX_SESSION_MANAGER_SUPPORT)
		{
			printf("\n Max Number of UDP Session Manager can be %d \n", UDP_MAX_SESSION_MANAGER_SUPPORT);
			exit(1);
		}
		printf("%50s\t%50d\n", "UDP_SESSION_MANAGER_INSTANCES", Global::UDP_SESSION_MANAGER_INSTANCES);
	}
}

void GConfig::get_udpSmCpu(std::string& Key)
{
	Value.clear();

	if(Key.compare("UDP_SESSION_MANAGER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::UDP_SESSION_MANAGER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "UDP_SESSION_MANAGER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::UDP_SESSION_MANAGER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_udpXdrForDns(std::string& Key)
{
	Value.clear();

	if(Key.compare("UDP_XDR_FOR_DNS") == 0)
	{
		fp >> Value;
		Global::UDP_XDR_FOR_DNS = Value.compare("true") == 0 ? true : false;
		printf("%50s\t%50s\n", "UDP_XDR_FOR_DNS", Value.c_str());
	}
}

void GConfig::get_noOfUdpFlusher(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_UDP_FLUSHER") == 0)
	{
		fp >> Value;
		Global::NO_OF_UDP_FLUSHER = atoi(Value.c_str());
		printf("%50s\t%50s\n", "NO_OF_UDP_FLUSHER", Value.c_str());
	}
}

void GConfig::get_udpFlushCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("UDP_FLUSHER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::UDP_FLUSHER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "UDP_FLUSHER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::UDP_FLUSHER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

/* DNS Session Manager Setting */

void GConfig::get_noOfDnsSmInstance(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_SESSION_MANAGER_INSTANCES") == 0)
	{
		fp >> Value;
		Global::DNS_SESSION_MANAGER_INSTANCES = atoi(Value.c_str());

		if(Global::DNS_SESSION_MANAGER_INSTANCES > DNS_MAX_SESSION_MANAGER_SUPPORT)
		{
			printf("\n Max Number of DNS Session Manager can be %d \n", DNS_MAX_SESSION_MANAGER_SUPPORT);
			exit(1);
		}
		printf("%50s\t%50d\n", "DNS_SESSION_MANAGER_INSTANCES", Global::DNS_SESSION_MANAGER_INSTANCES);
	}
}

void GConfig::get_dnsSmCpu(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_SESSION_MANAGER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::DNS_SESSION_MANAGER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "DNS_SESSION_MANAGER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::DNS_SESSION_MANAGER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_dnsSmCleanUpTime(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_SESSION_CLEAN_UP_TIMEOUT_SEC") == 0)
	{
		fp >> Value;
		Global::DNS_SESSION_CLEAN_UP_TIMEOUT_SEC = atoi(Value.c_str());
		printf("%50s\t%50d\n", "DNS_SESSION_CLEAN_UP_TIMEOUT_SEC", Global::DNS_SESSION_CLEAN_UP_TIMEOUT_SEC);
	}
}

void GConfig::get_noOfDnsFlusher(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_DNS_FLUSHER") == 0)
	{
		fp >> Value;
		Global::NO_OF_DNS_FLUSHER = atoi(Value.c_str());
		printf("%50s\t%50s\n", "NO_OF_DNS_FLUSHER", Value.c_str());
	}
}

void GConfig::get_dnsFlushCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_FLUSHER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::DNS_FLUSHER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "DNS_FLUSHER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::DNS_FLUSHER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_dnsWriteXdrFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("DNS_WRITE_XDR") == 0)
	{
		fp >> Value;
		if(Value.compare("true") == 0)
			Global::DNS_WRITE_XDR = true;
		else
			Global::DNS_WRITE_XDR = false;
		printf("%50s\t%50s\n", "DNS_WRITE_XDR", Value.c_str());
	}
}

/* UNMAPPED Session Manager Setting */

void GConfig::get_noOfUnmSmInstance(std::string& Key)
{
	Value.clear();

	if(Key.compare("UNM_SESSION_MANAGER_INSTANCES") == 0)
	{
		fp >> Value;
		Global::UNM_SESSION_MANAGER_INSTANCES = atoi(Value.c_str());

		if(Global::UNM_SESSION_MANAGER_INSTANCES > UNM_MAX_SESSION_MANAGER_SUPPORT)
		{
			printf("\n Max Number of UnMapped Session Manager can be %d \n", UNM_MAX_SESSION_MANAGER_SUPPORT);
			exit(1);
		}
		printf("%50s\t%50d\n", "UNM_SESSION_MANAGER_INSTANCES", Global::UNM_SESSION_MANAGER_INSTANCES);
	}
}

void GConfig::get_unmSmCpu(std::string& Key)
{
	Value.clear();

	if(Key.compare("UNM_SESSION_MANAGER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::UNMAPPED_SESSION_MANAGER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "UNM_SESSION_MANAGER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::UNMAPPED_SESSION_MANAGER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_noOfUnmFlusher(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_UNM_FLUSHER") == 0)
	{
		fp >> Value;
		Global::NO_OF_UNM_FLUSHER = atoi(Value.c_str());
		printf("%50s\t%50s\n", "NO_OF_UNM_FLUSHER", Value.c_str());
	}
}

void GConfig::get_unmFlushCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("UNM_FLUSHER_CPU_CORE") == 0)
	{
		fp >> Value;
		char * pch1;
		int cnt = 0;
		pch1 = strtok((char *)Value.c_str(),",");
		while (pch1 != NULL)
		{
			Global::UNM_FLUSHER_CPU_CORE[cnt] = atoi(pch1);
			buffer[0] = 0;
			sprintf(buffer, "UNM_FLUSHER_CPU_CORE[%d]", cnt);
			printf("%50s\t%50d\n", buffer, Global::UNM_FLUSHER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_unmWriteXdrFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("UNM_WRITE_XDR") == 0)
	{
		fp >> Value;
		if(Value.compare("true") == 0)
			Global::UNM_WRITE_XDR = true;
		else
			Global::UNM_WRITE_XDR = false;
		printf("%50s\t%50s\n", "UIP_WRITE_XDR", Value.c_str());
	}
}

void GConfig::openConfigFile(char *fileName)
{
	char probeConfigBaseDir[100];
	char *probeConfigDir;
	char *probeRootEnv;

	probeConfigDir = getenv("PROBE_CONF");
	probeRootEnv = getenv("PROBE_ROOT");

	if(probeConfigDir == NULL || probeRootEnv == NULL)
	{
		printf("\n\n\n  !!! ******* SpectaProbe Environment NOT Set ******* !!! \n\n\n");
		exit(1);
	}
	sprintf(probeConfigBaseDir, "%s/%s", probeConfigDir, fileName);
	fp.open(probeConfigBaseDir);


	if(fp.fail())
	{
		printf("  Error in Opening Configuration File : %s\n", probeConfigBaseDir);
		exit(1);
	}
}

void GConfig::closeConfigFile()
{ fp.close(); }

uint32_t GConfig::ipToLong(char *ip, uint32_t *plong)
{
	char *next = NULL;
	const char *curr = ip;
	unsigned long tmp;
	int i, err = 0;

	*plong = 0;
	for (i = 0; i < NUM_OCTETTS; i++) {
		tmp = strtoul(curr, &next, 10);
		if (tmp >= 256 || (tmp == 0 && next == curr)) {
			err++;
			break;
		}
		*plong = (*plong << 8) + tmp;
		curr = next + 1;
	}

	if (err)
		return 1;
	else
		return *plong;
}
