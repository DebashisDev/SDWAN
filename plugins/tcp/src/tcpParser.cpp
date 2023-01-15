/*
 * TCPProbe.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: debashis
 */


#include "tcpParser.h"

#include <pthread.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <ctype.h>
#include <algorithm>
#include <string>

#include "Log.h"

using namespace std;

tcpParser::tcpParser()
{
	this->psh 		= 0;
	this->rst 		= 0;
	this->syn 		= 0;
	this->fin 		= 0;
	this->window 	= 0;
	this->ack 		= 0;
	this->ackNo 	= 0;
	this->tcpHLen	= 0;
	this->pUt 		= new ProbeUtility();
}

tcpParser::~tcpParser()
{ delete(this->pUt); }

void tcpParser::parseTCPPacket(const BYTE packet, MPacket *msgObj)
{ 
	tcphdr 			*tcpHeader;
	msgObj->pLoad 	= 0;
	tcpHLen			= 0;
	tcpHeader = (struct tcphdr *)(packet);

//	msgObj->ipHLen = ((tcpHeader->doff) << 2);
	tcpHLen 	  = ((tcpHeader->doff) << 2);
	msgObj->sPort = ntohs((unsigned short int)tcpHeader->source);
	msgObj->dPort = ntohs((unsigned short int)tcpHeader->dest);

	switch(msgObj->ipVer)
	{
		case IPVersion4:
			msgObj->ipv4FlowId = pUt->getIpv4SessionKey(msgObj->pType, msgObj->direction, msgObj->sIp, msgObj->dIp, msgObj->sPort, msgObj->dPort);
			break;

		case IPVersion6:
			/* IPv6 FlowId is generated in Session Manager */
			break;
	}

	msgObj->pLoad = msgObj->ipTLen - (msgObj->ipHLen + tcpHLen);

	if(msgObj->pLoad > 0 && msgObj->pLoad >= Global::MAX_TCP_SIZE)
		msgObj->pLoad = Global::MAX_TCP_SIZE;

	if((msgObj->sPort == DNS_PORT) || (msgObj->dPort == DNS_PORT))
	{
		msgObj->tcpFlags = ACK_RCV;
		return;
	}
	msgObj->tcpSeqNo = VAL_ULONG(packet + 4);

	ack = tcpHeader->ack;
	psh = tcpHeader->psh;
	rst = tcpHeader->rst;
	syn = tcpHeader->syn;
	fin = tcpHeader->fin;

	/* ** Connection Request ** */
	if((syn) && (!ack) && (!psh) && (!fin))
	{ msgObj->tcpFlags = SYN_RCV; msgObj->pLoad = 0; }

	/* ** Connection Request with Response ** */
	else if((syn) && (ack) && (!psh) && (!fin))
	{ msgObj->tcpFlags = SYN_ACK_RCV; msgObj->pLoad = 0; }

	/* ** Connection Complete ** */
   	else if((!syn) && (ack) && (!rst) && (!fin) && (!psh))
	{
   		msgObj->tcpFlags = ACK_RCV;
	}

	/* ** Data Complete ** */
   	else if(psh)
	{ msgObj->tcpFlags = DATA_RCV; }

	/* ** Disconnect Request ** */
	else if(fin || rst)
	{ msgObj->tcpFlags = FIN_RCV; msgObj->pLoad = 0; }

	/* This should never happen, but in case */
	else
	{ msgObj->tcpFlags = TCP_UNKNOWN_PACKET_TYPE; msgObj->pLoad = 0; }

	/* ---------------- End of Session Management --------------------- */

	tcpHeader = NULL;
}

void tcpParser::checkAgentType(BYTE packet, MPacket *msgObj)
{
	int i, posIndex;
	const u_char *ch;
	std::string buffer, httpRspHdr;
	int length = 3;
	bool doFlag = false;

	string::iterator it;

	buffer.clear();
	httpRspHdr.clear();

	posIndex = 0;

	ch = packet;

	// Check for first 4 character as HTTP
	for(i = 0; i < length; i++) {
		httpRspHdr.append(1, *ch);
		ch++;
	}

	std::size_t pos = httpRspHdr.find("GET");

	if(pos != std::string::npos) {
		doFlag = true;
	}
	else {
		return;
	}

	int len = msgObj->pLoad - length;

	if(doFlag) {
		for(i = 0; i < len; i++) {
			if(*ch != CR) {
				if(*ch == COMMA)
					buffer.append(1, ';');
				else
					buffer.append(1, *ch);
				posIndex ++;
				ch++;

			}	// If
			else {

				std::size_t pos = buffer.find("User-Agent:");

//				if(pos != std::string::npos) {
//					strncpy(msgObj->httpAgent, buffer.c_str(), (HTTP_AGENT_LEN - 1));
//					//printf("%s\n", msgObj->httpAgent);
//				}

				ch += 2;
				buffer.clear();
			} // Else
		}	// For Loop
	}	// End of If Condition
}


vector<string> tcpParser::split(string str, char delimiter)
{
	vector<string> internal;
	stringstream ss(str);
	string token;

	while(getline(ss, token, delimiter))
	    internal.push_back(token);

	return internal;
}
