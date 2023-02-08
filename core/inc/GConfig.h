/*
 * GConfig.h
 *
 *  Created on: 26-Jul-2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_GCONFIG_H_
#define CORE_SRC_GCONFIG_H_

#include <string.h>
#include <fstream>
#include <iostream>

#include "SpectaTypedef.h"

#define NUM_OCTETTS 4

using namespace std;

class GConfig
{
	private:
		ifstream fp;
		string Key, Value;

		char 	buffer[50];
	public:
		GConfig();
		~GConfig();

		void	get_probeId(std::string& Key);
		void	get_logLevel(std::string& Key);
		void	get_printStats(std::string& Key);
		void	get_printStatsFrequency(std::string& Key);
		void	get_logStatsFrequency(std::string& Key);
		void	get_logDir(std::string& Key);
		void	get_dataDir(std::string& Key);
		void	get_xdrDir(std::string& Key);
		void	get_unKnownXdrDir(std::string& Key);
		void	get_adminFlag(std::string& Key);
		void	get_adminPort(std::string& Key);
		void	get_ethernetInterface(std::string& Key);
		void	get_PPSPerInterface(std::string& Key);
		void	get_interfaceCPU(std::string& Key);
		void	get_routerCPU(std::string& Key);
		void	get_PPSCap(std::string& Key);
		void	get_packetLen(std::string& Key);
		void	get_IPV4Range(std::string& Key);
		void 	converSubNetToRange(char *ipr, char *Start, char *End);
		void	get_routerPerInterface(std::string& Key);
		void	get_ProcessOutOfRange(std::string& Key);
		void	get_processAckFlag(std::string& Key);
		void	get_ackCrateFlag(std::string& Key);
		void	get_maxTcpSize(std::string& Key);
		void	get_udpXdrForDns(std::string& Key);
		void	get_DnsAnswerCount(std::string& Key);
		void	get_smTimeLimit(std::string& Key);
		void	get_smPacketLimit(std::string& Key);
		void	get_ipSmCleanUpTime(std::string& Key);
		void	get_dnsSmCleanUpTime(std::string& Key);


		void	get_ipWriteXdrFlag(std::string& Key);
		void	get_dnsWriteXdrFlag(std::string& Key);
		void	get_unmWriteXdrFlag(std::string& Key);

		void	get_noOfTcpSmInstance(std::string& Key);
		void	get_tcpSmCpu(std::string& Key);
		void	get_noOfTcpFlusher(std::string& Key);
		void	get_tcpFlushCPU(std::string& Key);

		void	get_noOfUdpSmInstance(std::string& Key);
		void	get_udpSmCpu(std::string& Key);
		void	get_noOfUdpFlusher(std::string& Key);
		void	get_udpFlushCPU(std::string& Key);

		void	get_noOfDnsSmInstance(std::string& Key);
		void	get_dnsSmCpu(std::string& Key);
		void	get_noOfDnsFlusher(std::string& Key);
		void	get_dnsFlushCPU(std::string& Key);

		void	get_noOfUnmSmInstance(std::string& Key);
		void	get_unmSmCpu(std::string& Key);
		void	get_noOfUnmFlusher(std::string& Key);
		void	get_unmFlushCPU(std::string& Key);


		void 	initialize(char *fileName);
		void 	openConfigFile(char *fileName);
		void 	closeConfigFile();
		void 	loadPuglinConfigs(char *fileName);
		uint32_t ipToLong(char *ip, uint32_t *plong);

};

#endif /* CORE_SRC_GCONFIG_H_ */
