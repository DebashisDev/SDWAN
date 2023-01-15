/*
 * Ethernet.h
 *
 *  Created on: 04-Jul-2016
 *      Author: debashis
 */

#ifndef PACKETSOURCE_ETH_SRC_ETH_H_
#define PACKETSOURCE_ETH_SRC_ETH_H_

#include <pcap.h>
#include <unistd.h>
#include <signal.h>

#include "smGlobal.h"
#include "BaseConfig.h"
#include "Log.h"
#include "SpectaTypedef.h"

using namespace std;

class EthernetSource : BaseConfig
{
	public:
		EthernetSource(uint16_t perListenerRouters, uint16_t intfId);
		~EthernetSource();
		void packetReaderCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
		void start();
		static void pcapCallBackFunction(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

		int pcapCaptureLoop(int pkt_count = -1)
		{ return pcap_loop(pcapHandle, pkt_count, pcapCallBackFunction, reinterpret_cast<u_char *>(this)); }

		bool  	isRepositoryInitialized();

	private:
		bool 		repoInitStatus;
		BYTE 		pkt;
		uint16_t 	len;
		uint16_t 	intfId;
		uint16_t 	tIdx;
		uint16_t 	pTidx;
		uint16_t 	ROUTER_TO_PROCESS;
		uint16_t 	END_ROUTER_ID;
		uint16_t 	maxPktLen;
		uint16_t 	copy_len;
		uint32_t 	noOfPackets;
		uint32_t 	MAX_PKT_ALLOWED_PER_TIME_INDEX;
		uint64_t 	tv_sec;
		uint64_t 	tv_nsec;

		string 		intfName;
		pcap_t*		pcapHandle;
		char 		errbuf[PCAP_ERRBUF_SIZE];
		void		resetCounters();
		void 		addCounters(uint16_t infId, uint16_t len);
		void 		countDiscardedPkt();
};

#endif /* PACKETSOURCE_ETH_SRC_ETH_H_ */
