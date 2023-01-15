/*
 * TCPFlusherUtility.h
 *
 *  Created on: Dec 21, 2016
 *      Author: Deb
 */

#ifndef PLUGINS_TCP_SRC_TCPFLUSHERUTILITY_H_
#define PLUGINS_TCP_SRC_TCPFLUSHERUTILITY_H_

#include <unistd.h>

#include "dnsData.h"
#include "IPGlobal.h"
#include "ProbeUtility.h"
#include "smGlobal.h"

#define IPV6_PREFIX_LAN		19

using namespace std;

class flusherUtility
{
	private:

			void 			createTCPXdr(tcpSession *pIpSession, char *xdr, string upVol, string dnVol);
			void 			createUDPXdr(tcpSession *pIpSession, char *xdr, string upVol, string dnVol);

			void 			lockDnsMap();
			void 			unLockDnsMap();

			void 			formateIPv6(char *buffer);

			uint32_t		vpsTimeKeys[10000];

			char 			sIpAddress[IPV4_ADDR_LEN];
			char 			dIpAddress[IPV4_ADDR_LEN];

			bool 			someChecks(tcpSession *pIpSession);
			void			swap3(uint64_t *a, uint64_t *b, uint64_t *c);
			void			swap4(uint64_t *a, uint64_t *b, uint64_t *c,  uint64_t *d);
			string 			getURLLookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap);
			string			findDns(uint32_t dIp);

	public:
			flusherUtility(uint16_t instanceId);
			~flusherUtility();

			string		getResolvedIp4(uint32_t dIp);
			void 		buildTcpXdr(tcpSession *pIpSession, char *csvXDR);
			void		buildUdpXdr(udpSession *pUdpSession, char *xdr);
			void 		buildDnsXdr(dnsSession *pDnsSession, char *csvXDR);
};

#endif /* PLUGINS_TCP_SRC_TCPFLUSHERUTILITY_H_ */
