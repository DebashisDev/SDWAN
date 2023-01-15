/*
 * adminPortReader.cpp
 *
 *  Created on: Aug 7, 2017
 *      Author: Debashis
 */

#include "AdminPortReader.h"

#include <zmq.h>
#include <unistd.h>


AdminPortReader::AdminPortReader()
{
	this->_name = "AdminPortReader";
	this->setLogLevel(Log::theLog().level());

	this->adminZmqContext = NULL;
	this->adminZmqRequester = NULL;

	this->pGConfig		= new GConfig();
}

AdminPortReader::~AdminPortReader()
{ delete (this->pGConfig); }

void AdminPortReader::run()
{
	bool isStatsInitialized = false;
	char buffer[100];
	char buffer1[100];
	int zmqConnect = -1;

	buffer[0] = buffer1[0] = 0;
 	TheLog_nc_v1(Log::Info, name()," Opening Admin Zmq Connection to [%s]...", Global::ADMIN_PORT.c_str());
	adminZmqContext = zmq_ctx_new ();
	adminZmqRequester = zmq_socket (adminZmqContext, ZMQ_REP);
	int rc = zmq_bind(adminZmqRequester, Global::ADMIN_PORT.c_str());

	while(Global::PROBE_STATS_RUNNING_STATUS)
	{
		sleep(5);
		int num = zmq_recv(adminZmqRequester, buffer, sizeof(buffer), 0);

		printf("Command Received:: %s [%d]\n", buffer, num);
		buffer1[0] = 0;
		strncpy(buffer1, buffer, num);
		printf("Command Received:: %s [%d]\n", buffer1, num);

		zmq_send(adminZmqRequester, "SUCCESS", 8, 0);

		if(strstr(buffer, "LOAD") != NULL)
			refreshConfig();
		else if(strstr(buffer, "PAUSE_TRAFFIC") != NULL)
		{
			for(int infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
			{
				Global::PACKET_PROCESSING[infCounter] = false;
			}
		}
		else if(strstr(buffer, "RESUME_TRAFFIC") != NULL)
		{
			for(int infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
			{
				Global::PACKET_PROCESSING[infCounter] = true;
				sleep(30);
			}
		}
		else
			printf("****** Invalid Command ....!!!! \n");

		strcpy(buffer, "NA");
		strcpy(buffer1, "NA");
 	}
	printf("  Admin Reader Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}


void AdminPortReader::refreshConfig()
{
	char *pchHash, *pchComma;
	char writeXdr[10];
	char flushFlag1[10];

	uint16_t cnt, cnt1;
	uint32_t x = 0;

	cnt = cnt1 = 0;
	size_t pos = 0;
	std::string token;

	printf("\n Re-loading Configurations...\n");

	writeXdr[0] = flushFlag1[0] = 0;

	openConfigFile("probe.config");

	while(!fp.eof())
	{
		Key.clear();
		fp >> Key;

		pGConfig->get_solarTimeStamp(Key);						/* SOLARFLARE_HW_TIMESTAMP */
		pGConfig->get_ProcessCDN(Key);
		pGConfig->get_CdnIPRangeV4(Key);
		pGConfig->get_CdnIPRangeV6(Key);
		pGConfig->get_ipv6ProcessingFlag(Key);
		pGConfig->get_vpsPacketPerSec(Key);
		pGConfig->get_udpXdrForDns(Key);
		pGConfig->get_DnsAnswerCount(Key);
		pGConfig->get_IPV4Range(Key);
		pGConfig->get_ipv6Range(Key);
		pGConfig->get_maxTcpSize(Key);
		pGConfig->get_ProcessOutOfRange(Key);
		pGConfig->get_userAgentFlag(Key);
		pGConfig->get_checkDuplicateFlag(Key);
		pGConfig->get_processAckFlag(Key);
		pGConfig->get_ackCrateFlag(Key);
		pGConfig->get_printStats(Key);
		pGConfig->get_printStatsFrequency(Key);
		pGConfig->get_logStatsFrequency(Key);
		pGConfig->get_smTimeLimit(Key);
		pGConfig->get_ipSmCleanUpTime(Key);						/* IP_SESSION_CLEAN_UP_TIMEOUT_SEC */
		pGConfig->get_dnsSmCleanUpTime(Key);					/* DNS_SESSION_CLEAN_UP_TIMEOUT_SEC */
		pGConfig->get_ipWriteXdrFlag(Key);						/* IP_WRITE_XDR */
		pGConfig->get_dnsWriteXdrFlag(Key);						/* DNS_WRITE_XDR */
	}
	closeConfigFile();
}

void AdminPortReader::openConfigFile(char *fileName)
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

void AdminPortReader::closeConfigFile()
{ fp.close(); }

uint32_t AdminPortReader::ipToLong(char *ip, uint32_t *plong)
{
	char *next = NULL;
	const char *curr = ip;
	unsigned long tmp;
	int i, err = 0;

	*plong = 0;
	for (i = 0; i < NUM_OCTETTS; i++)
	{
		tmp = strtoul(curr, &next, 10);
		if (tmp >= 256 || (tmp == 0 && next == curr))
		{
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
