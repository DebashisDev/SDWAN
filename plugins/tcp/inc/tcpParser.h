/*
 * PTCP.h
 *
 *  Created on: Nov 29, 2015
 *      Author: debashis
 */

#ifndef INC_TCPPROBE_H_
#define INC_TCPPROBE_H_

#include <vector>
#include <string>
#include <sstream>

#include "SpectaTypedef.h"
#include "IPGlobal.h"
#include "ProbeUtility.h"
#include "smGlobal.h"

using namespace std;

#define TCPHDR 			20
#define MAX_TCP_PAYLOAD 20

#define LF              10
#define CR				13
#define COMMA			44
#define SEMICOLON		59

class tcpParser
{
	private:
		uint16_t 		psh, rst, syn, fin, window, ack, ackNo;
		uint16_t		tcpHLen;
		ProbeUtility*	pUt;

	public:
		tcpParser();
		~tcpParser();

		void parseTCPPacket(const BYTE packet, MPacket *msgObj);
		void checkAgentType(const BYTE packet, MPacket *msgObj);
		vector<string> split(string str, char delimiter);
};

#endif  /* INC_TCPPROBE_H_ */
