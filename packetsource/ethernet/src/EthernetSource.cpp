/*
 * Ethernet.cpp
 *
 *  Created on: 04-Jul-2016
 *      Author: debashis
 */

#include "EthernetSource.h"
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

uint64_t  	n_rx_pkts_0;
uint64_t  	n_rx_pkts_1;
uint64_t  	n_rx_pkts_2;
uint64_t  	n_rx_pkts_3;
uint64_t  	n_rx_pkts_4;
uint64_t  	n_rx_pkts_5;
uint64_t  	n_rx_pkts_6;
uint64_t  	n_rx_pkts_7;

uint64_t  	n_rx_bytes_0;
uint64_t  	n_rx_bytes_1;
uint64_t  	n_rx_bytes_2;
uint64_t  	n_rx_bytes_3;
uint64_t  	n_rx_bytes_4;
uint64_t  	n_rx_bytes_5;
uint64_t  	n_rx_bytes_6;
uint64_t  	n_rx_bytes_7;


EthernetSource::EthernetSource(uint16_t perListenerRouters, uint16_t intfid)
{
	this->_name = "EthernetSource";
	this->setLogLevel(Log::theLog().level());

	this->repoInitStatus	= false;
	this->pkt 				= NULL;
	this->len 				= 0;
	this->intfId 			= intfid;
	this->intfName 			= Global::ETHERNET_INTERFACES[intfId];
	this->tIdx 				= 0;
	this->pTidx 			= 0;
	this->ROUTER_TO_PROCESS = 0;
	this->maxPktLen 		= Global::MAX_PKT_LEN_PER_INTERFACE[intfId];
	this->copy_len 			= 0;
	this->noOfPackets		= 0;
	this->tv_sec 			= 0;
	this->tv_nsec 			= 0;
	this->pcapHandle 		= NULL;
	this->END_ROUTER_ID 	= perListenerRouters;
	this->MAX_PKT_ALLOWED_PER_TIME_INDEX = 0;

}

EthernetSource::~EthernetSource()
{ }

bool EthernetSource::isRepositoryInitialized()
{ return repoInitStatus; }

void EthernetSource::resetCounters()
{
	n_rx_bytes_0 	= 0;
	n_rx_pkts_0 	= 0;

	n_rx_bytes_1 	= 0;
	n_rx_pkts_1 	= 0;

	n_rx_bytes_2 	= 0;
	n_rx_pkts_2 	= 0;

	n_rx_bytes_3 	= 0;
	n_rx_pkts_3 	= 0;

	n_rx_bytes_4 	= 0;
	n_rx_pkts_4 	= 0;

	n_rx_bytes_5 	= 0;
	n_rx_pkts_5 	= 0;

	n_rx_bytes_6 	= 0;
	n_rx_pkts_6 	= 0;

	n_rx_bytes_7 	= 0;
	n_rx_pkts_7 	= 0;
}

void EthernetSource::addCounters(uint16_t infId, uint16_t len)
{
	switch(infId)
	{
		case 0:
				n_rx_bytes_0 += len;
				n_rx_pkts_0++;
				break;

		case 1:
				n_rx_bytes_1 += len;
				n_rx_pkts_1++;
				break;

		case 2:
				n_rx_bytes_2 += len;
				n_rx_pkts_2++;
				break;

		case 3:
				n_rx_bytes_3 += len;
				n_rx_pkts_3++;
				break;

		case 4:
				n_rx_bytes_4 += len;
				n_rx_pkts_4++;
				break;

		case 5:
				n_rx_bytes_5 += len;
				n_rx_pkts_5++;
				break;

		case 6:
				n_rx_bytes_6 += len;
				n_rx_pkts_6++;
				break;

		case 7:
				n_rx_bytes_7 += len;
				n_rx_pkts_7++;
				break;
	}
}

void EthernetSource::packetReaderCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if(Global::PKT_LISTENER_DAYCHANGE_INDICATION[intfId])
	{
		switch(intfId)
		{
			case 0:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_0);
				break;
			case 1:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_1);
				break;
			case 2:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_2);
				break;
			case 3:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_3);
				break;
			case 4:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_4);
				break;
			case 5:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_5);
				break;
			case 6:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_6);
				break;
			case 7:
				TheLog_nc_v2(Log::Info, name()," Day Change Indication received. Interface [%s] -> Pkts Processed [%lu]. Reseting counter.", intfName.c_str(), n_rx_pkts_7);
				break;
		}

		resetCounters();
		Global::PKT_LISTENER_DAYCHANGE_INDICATION[intfId] = false;
	}

	if(!Global::PKT_LISTENER_RUNNING_STATUS[intfId])
	{
		pcap_breakloop(pcapHandle);
		return;
	}

	addCounters(intfId, header->len);

	tIdx = PKT_WRITE_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	if(pTidx != tIdx)
	{
		ROUTER_TO_PROCESS = 0;
		noOfPackets = 0;
		pTidx = tIdx;
	}

	pkt = (BYTE)packet;

	uint16_t protocol = pkt[12] * 256 + pkt[13];		/* Ethernet Containing Protocol */

	switch(protocol)
	{
		case ETH_IP:				/* Internet Protocol packet	*/
		case ETH_8021Q:				/* 802.1Q VLAN Extended Header  */
		case ETH_MPLS_UC:			/* MPLS */
						break;
		case ETH_IPV6:				/* IPv6 over bluebook		*/
						return;
						break;
		default:
						countDiscardedPkt();
						return;
						break;
	}

	len = header->len;

	tv_sec = Global::CURRENT_EPOCH_SEC;
	tv_nsec = Global::CURRENT_EPOCH_NANO_SEC;

	if(len >= maxPktLen) copy_len = maxPktLen;
	else copy_len = len;

	if(!Global::PACKET_PROCESSING[intfId]) return; /* If packet processing is false don't Push Packet */

	if(PKTStore::cnt[intfId][ROUTER_TO_PROCESS][tIdx + 2] != 0)
		return;

	if(PKTStore::busy[intfId][ROUTER_TO_PROCESS][tIdx] || PKTStore::cnt[intfId][ROUTER_TO_PROCESS][tIdx] >= MAX_PKT_ALLOWED_PER_TIME_INDEX)
		return;

	RawPkt *rpkt = PKTStore::store[intfId][ROUTER_TO_PROCESS][tIdx][PKTStore::cnt[intfId][ROUTER_TO_PROCESS][tIdx]];
	rpkt->len = len;
	rpkt->tv_sec = tv_sec;
	rpkt->tv_nsec = tv_nsec;
	memcpy((void *)rpkt->pkt, (const void *)pkt, copy_len);
	PKTStore::cnt[intfId][ROUTER_TO_PROCESS][tIdx]++;

	noOfPackets++ ;

	if(noOfPackets >= MAX_PKT_ALLOWED_PER_TIME_INDEX)
	{
		ROUTER_TO_PROCESS++;

		if(ROUTER_TO_PROCESS >= Global::ROUTER_PER_INTERFACE[intfId])
			ROUTER_TO_PROCESS = 0;

		noOfPackets = 0;
	}
}

void EthernetSource::countDiscardedPkt()
{ Global::DISCARDED_PACKETS[intfId]++; }

void monitor(int ethintfId);

void* monitor_fn(void* arg)
{
  int id = *(int *)arg;
  monitor(id);
  return NULL;
}

void EthernetSource::start()
{
	pthread_t thread_id;

	MAX_PKT_ALLOWED_PER_TIME_INDEX = (int)(((Global::PPS_PER_INTERFACE[intfId] / Global::ROUTER_PER_INTERFACE[intfId]) /100 ) * Global::PPS_CAP_PERCENTAGE[intfId]);

	printf("EthernetSource started with [%d] Routers for Interface [%d]->[%s] with %d% [%d] pps cap\n", END_ROUTER_ID, intfId, intfName.c_str(), Global::PPS_CAP_PERCENTAGE[intfId], MAX_PKT_ALLOWED_PER_TIME_INDEX);
	TheLog_nc_v5(Log::Info, name(),"  EthernetSource started with [%d] Routers for Interface [%d]->[%s] with %d% [%d] pps cap\n", END_ROUTER_ID, intfId, intfName.c_str(), Global::PPS_CAP_PERCENTAGE[intfId], MAX_PKT_ALLOWED_PER_TIME_INDEX);

	pthread_create(&thread_id, NULL, monitor_fn, (void *)&intfId);

	repoInitStatus = true;

	pcapHandle = pcap_open_live(this->intfName.c_str(), BUFSIZ, 1, -1, errbuf);

	if(pcapHandle == NULL)
	{
		cout << "ERROR !!! In reading Ethernet " << this->intfName.c_str() << endl;
		exit(1);
	}

	if(pcapHandle != NULL) {
		int ret = this->pcapCaptureLoop();

		if (ret == -2)
			printf("NIC   [%10s] Shutdown Completed\n\n", this->intfName.c_str());
		else if (ret == 0)
			printf("pcap_loop no more packets to read ...\n");
	}

	if(pcapHandle != NULL)
		pcap_close(pcapHandle);
}

void EthernetSource::pcapCallBackFunction(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
		EthernetSource *sniffer=reinterpret_cast<EthernetSource *>(args);
		sniffer->packetReaderCallback(args,header,packet);
}

void monitor(int ethintfId)
{
	/* Print approx packet rate and bandwidth every second. */
	uint64_t now_bytes, prev_bytes;
	struct timeval start, end;
	struct tm *now_tm;
	int prev_pkts, now_pkts;
	int ms, pkt_rate, mbps;

	switch(ethintfId)
	{
		case 0:
				prev_pkts = n_rx_pkts_0;
				prev_bytes = n_rx_bytes_0;
				break;

		case 1:
				prev_pkts = n_rx_pkts_1;
				prev_bytes = n_rx_bytes_1;
				break;

		case 2:
				prev_pkts = n_rx_pkts_2;
				prev_bytes = n_rx_bytes_2;
				break;

		case 3:
				prev_pkts = n_rx_pkts_3;
				prev_bytes = n_rx_bytes_3;
				break;

		case 4:
				prev_pkts = n_rx_pkts_4;
				prev_bytes = n_rx_bytes_4;
				break;

		case 5:
				prev_pkts = n_rx_pkts_5;
				prev_bytes = n_rx_bytes_5;
				break;

		case 6:
				prev_pkts = n_rx_pkts_6;
				prev_bytes = n_rx_bytes_6;
				break;

		case 7:
				prev_pkts = n_rx_pkts_7;
				prev_bytes = n_rx_bytes_7;
				break;
	}

	gettimeofday(&start, NULL);

	now_tm = localtime(&start.tv_sec);

	while(Global::PKT_LISTENER_RUNNING_STATUS[ethintfId])
	{
		sleep(1);
		gettimeofday(&end, NULL);

		now_tm = localtime(&end.tv_sec);

		switch(ethintfId)
		{
			case 0:
					now_pkts = n_rx_pkts_0;
					now_bytes = n_rx_bytes_0;
					break;

			case 1:
					now_pkts = n_rx_pkts_1;
					now_bytes = n_rx_bytes_1;
					break;

			case 2:
					now_pkts = n_rx_pkts_2;
					now_bytes = n_rx_bytes_2;
					break;

			case 3:
					now_pkts = n_rx_pkts_3;
					now_bytes = n_rx_bytes_3;
					break;

			case 4:
					now_pkts = n_rx_pkts_4;
					now_bytes = n_rx_bytes_4;
					break;

			case 5:
					now_pkts = n_rx_pkts_5;
					now_bytes = n_rx_bytes_5;
					break;

			case 6:
					now_pkts = n_rx_pkts_6;
					now_bytes = n_rx_bytes_6;
					break;

			case 7:
					now_pkts = n_rx_pkts_7;
					now_bytes = n_rx_bytes_7;
					break;
		}

		if(now_pkts < prev_pkts)
			prev_pkts = now_pkts;
		if(now_bytes < prev_bytes)
			prev_bytes = now_bytes;

		ms = (end.tv_sec - start.tv_sec) * 1000;
		ms += (end.tv_usec - start.tv_usec) / 1000;
		pkt_rate = (int) ((int64_t) (now_pkts - prev_pkts) * 1000 / ms);
		mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);

		Global::PKTS_TOTAL_INTF[ethintfId] = now_pkts;
		Global::PKT_RATE_INTF[ethintfId] = pkt_rate;
		Global::BW_MBPS_INTF[ethintfId] = mbps;

		prev_pkts = now_pkts;
		prev_bytes = now_bytes;
		start = end;
	}
}

