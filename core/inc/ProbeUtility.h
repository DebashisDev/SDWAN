/*
 * ProbeUtility.h
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#ifndef SRC_PROBEUTILITY_H_
#define SRC_PROBEUTILITY_H_


#include <netinet/tcp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include <stdlib.h>
#include <vector>
#include <sstream>

#include "Log.h"
#include "IPGlobal.h"
#include "smGlobal.h"
#include "BaseConfig.h"

#define BASE		10000000000

#define handle_error_en(en, msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

class ProbeUtility : BaseConfig
{
	public:
		ProbeUtility();
		~ProbeUtility();

		void 	 	Append(char *original, const char *add);
		void	 	getIPHex(char *address, char *hexaddress);
		void	 	fillIP(char *address, char *fillInAddress);
		void	 	ExtractIP4Address(const BYTE packet, char *ipBuffer, uint32_t loc);
		void	 	ExtractIP6Address(const BYTE packet, char *ipBuffer, uint32_t loc);
		void	 	ExtractIP6Prefix(const BYTE packet, char *ipBuffer, uint32_t loc, uint32_t end);
		uint16_t 	parseTcpTimeStamp(struct tcphdr *tcp, ULONG *tsval, ULONG *tsecr);
		void 		pinThread(pthread_t th, uint16_t core_num);
		vector<string> split(string str, char delimiter);

		uint8_t		matchIPs(uint32_t src, uint32_t dst, uint32_t net, uint32_t num_bits);
		uint8_t 	matchIP(uint32_t ip_to_check, uint32_t net, uint32_t num_bits);
		uint32_t 	HextoDigits(char *hexadecimal);
		uint32_t 	getLength(const BYTE packet, size_t offset);

		void 		HEXDUMP(const void* pv, int len);
		uint64_t 	getIpv4SessionKey(uint8_t &protocol, uint8_t direction, uint32_t &sourceIp, uint32_t &destIp, uint16_t &sourcePort, uint16_t &destPort);
		void 	 	dnsDumpIpv4Data(string dir);
		void 		loadResolvedIpv4(string dir);
};

#endif /* SRC_PROBEUTILITY_H_ */
