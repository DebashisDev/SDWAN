/*
 * Common.h
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#ifndef INC_SPECTATYPEDEF_H_
#define INC_SPECTATYPEDEF_H_

#include <ctype.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>


typedef unsigned char*	BYTE;
typedef unsigned long	ULONG;

static const char* HexLkp2 =
	"000102030405060708090A0B0C0D0E0F"
	"101112131415161718191A1B1C1D1E1F"
	"202122232425262728292A2B2C2D2E2F"
	"303132333435363738393A3B3C3D3E3F"
	"404142434445464748494A4B4C4D4E4F"
	"505152535455565758595A5B5C5D5E5F"
	"606162636465666768696A6B6C6D6E6F"
	"707172737475767778797A7B7C7D7E7F"
	"808182838485868788898A8B8C8D8E8F"
	"909192939495969798999A9B9C9D9E9F"
	"A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
	"B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
	"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
	"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
	"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
	"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

#ifndef VAL_BYTE
#define VAL_BYTE(p)     (*(p))
#endif

#ifndef VAL_USHORT
#define VAL_USHORT(p)   (ntohs(*((uint16_t *)(p) )))
#endif

#ifndef VAL_ULONG
#define	VAL_ULONG(p)	(ntohl(*((uint32_t *)(p) )))
#endif

enum ipVer
{
	IPVersion4 		= 4,
	IPVersion6 		= 6
};

enum interfaceType
{
	PCAP = 0,
	ETHERNET,
	SOLARFLARE
};

static const char* B2H[] = {"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"};

inline char *Byte2Hex(char a1, char *pBuf)
{
	uint16_t * pptbl = (uint16_t*) HexLkp2;
	uint16_t * ppout = (uint16_t*) pBuf;
    *ppout = pptbl[a1];
    pBuf[2] = 0;
    return pBuf + 2;
}

inline char *Long2Hex(uint32_t a1, char *pBuf)
{
	uint16_t * pptbl = (uint16_t*) HexLkp2;
	uint16_t * ppout = (uint16_t*) pBuf;

    *ppout++=pptbl[(a1&0xff000000)>>24];
    *ppout++=pptbl[(a1&0x00ff0000)>>16];
    *ppout++=pptbl[(a1&0x0000ff00)>>8 ];
    *ppout++=pptbl[a1&0x000000ff];
    pBuf[8]=0;
    return pBuf+8;
}

inline char  *Long2IPHex(uint32_t a1, char *pBuf)
 {
		uint16_t * pptbl = (uint16_t*) HexLkp2;
		uint16_t * ppout = (uint16_t*) pBuf;

     *ppout=pptbl[(a1&0xff000000)>>24]; ppout = (uint16_t*) (pBuf+3);
     *ppout=pptbl[(a1&0x00ff0000)>>16]; ppout = (uint16_t*) (pBuf+6);
     *ppout=pptbl[(a1&0x0000ff00)>>8];  ppout = (uint16_t*) (pBuf+9);
     *ppout=pptbl[(a1&0x000000ff)];
		pBuf[2]=pBuf[5]=pBuf[8]='.';
     pBuf[11]=0;

     return pBuf+11;
 }

inline char  Hex2Byte(char n1, char n2)
{
	n1=toupper(n1);
	n2=toupper(n2);

	char b1=(char *) isdigit(n1)?(n1-'0'):(n1-'A'+10);
	char b2=(char *) isdigit(n2)?(n2-'0'):(n2-'A'+10);

	return (b1<<4)|b2;
}

inline char * ExtractIP(char *pszString, char *pBuf)
{
	const char * pptr = pszString;
	char b[4];
	b[0]=Hex2Byte(pptr[0],pptr[1]);
	b[1]=Hex2Byte(pptr[3],pptr[4]);
	b[2]=Hex2Byte(pptr[6],pptr[7]);
	b[3]=Hex2Byte(pptr[9],pptr[10]);

	sprintf((char *)pBuf, "%u.%u.%u.%u", b[0],b[1],b[2],b[3]);
	return pBuf;
}

inline void long2Ip(uint32_t ipLong, char *ipAddress)
{
    unsigned char bytes[4];
    bytes[0] = ipLong & 0xFF;
    bytes[1] = (ipLong >> 8) & 0xFF;
    bytes[2] = (ipLong >> 16) & 0xFF;
    bytes[3] = (ipLong >> 24) & 0xFF;
    sprintf(ipAddress, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

#endif /* INC_SPECTATYPEDEF_H_ */
