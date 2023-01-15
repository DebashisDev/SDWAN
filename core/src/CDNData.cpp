/*
 * CDNData.cpp
 *
 *  Created on: 03-Sep-2019
 *      Author: singh
 */

#include "CDNData.h"

CDNData::CDNData(uint16_t intfid, uint16_t rid)
{
	this->_name = "CDNData";
	this->setLogLevel(Log::theLog().level());

	this->interfaceId 	= intfid;
	this->routerId 		= rid;
	this->volume		= 0;
	this->curSec		= 0;
	this->dir			= 0;

	printf("** CDNData:: Initialized for Interface [%d]\n", this->interfaceId);
}

CDNData::~CDNData()
{ }

void CDNData::updateCDNData(uint16_t curMin, MPacket *msgObj)
{
	volume = msgObj->frSize;
	dir = msgObj->direction;
	curSec = msgObj->frTimeEpochSec % 100;

	/* 	Write in curMin index based on Odd or Even min
	**	if curMin = 3, write in _1 if curMin = 4 write in _0
	**	Reading will happen opposite
	*/

	uint16_t t_index = curMin % 2;

	processCdnData(cdn_i_r_t[interfaceId][routerId][t_index]);
}

void CDNData::processCdnData(cdnData (&cdn)[CDN_TIME_INDEX])
{
	cdn[curSec].totalVol += volume;
	if(dir == 1)
		cdn[curSec].upTotalVol += volume;
	else if(dir == 2)
		cdn[curSec].dnTotalVol += volume;
}

void CDNData::setCDNData(uint16_t curMin)
{
	uint16_t t_index = curMin % 2;
	if(t_index == 0) t_index = 1;
	else if(t_index == 1) t_index = 0;

	cdnData cdn;

	cdn = calculateCdnData(cdn_i_r_t[interfaceId][routerId][t_index]);

	Global::CDN_MBPS_i_r[interfaceId][routerId].Bw = cdn.Bw;
	Global::CDN_MBPS_i_r[interfaceId][routerId].upBw = cdn.upBw;
	Global::CDN_MBPS_i_r[interfaceId][routerId].dnBw = cdn.dnBw;
	Global::CDN_MBPS_i_r[interfaceId][routerId].totalVol = cdn.totalVol;
	Global::CDN_MBPS_i_r[interfaceId][routerId].upTotalVol = cdn.upTotalVol;
	Global::CDN_MBPS_i_r[interfaceId][routerId].dnTotalVol = cdn.dnTotalVol;
	Global::CDN_MBPS_i_r[interfaceId][routerId].peakTotalVol 	= cdn.peakTotalVol;
	Global::CDN_MBPS_i_r[interfaceId][routerId].peakUpTotalVol = cdn.peakUpTotalVol;
	Global::CDN_MBPS_i_r[interfaceId][routerId].peakDnTotalVol = cdn.peakDnTotalVol;

	Global::CDN_MBPS_i_r[interfaceId][routerId].avgTotalBw= cdn.avgTotalBw;
	Global::CDN_MBPS_i_r[interfaceId][routerId].avgUpBw 	= cdn.avgUpBw;
	Global::CDN_MBPS_i_r[interfaceId][routerId].avgDnBw 	= cdn.avgDnBw;

}

cdnData CDNData::calculateCdnData(cdnData (&cdn)[CDN_TIME_INDEX])
{
	uint32_t samplesTotal 	= 0;
	uint32_t samplesUp 		= 0;
	uint32_t samplesDn 		= 0;
	cdnData  cdndata;

	cdndata.Bw 	= 0;
	cdndata.upBw = 0;
	cdndata.dnBw = 0;

	cdndata.totalVol 	= 0;
	cdndata.upTotalVol 	= 0;
	cdndata.dnTotalVol 	= 0;
	cdndata.peakTotalVol = 0;
	cdndata.peakUpTotalVol = 0;
	cdndata.peakDnTotalVol = 0;
	cdndata.avgTotalBw 	= 0;
	cdndata.avgUpBw 		= 0;
	cdndata.avgDnBw 		= 0;


	for(uint16_t i = 0; i < CDN_TIME_INDEX; i++)
	{
		if(cdn[i].totalVol > 0)
			samplesTotal++;

		cdndata.totalVol += cdn[i].totalVol;

		if(cdn[i].totalVol > cdndata.peakTotalVol)
			cdndata.peakTotalVol = cdn[i].totalVol;
		cdn[i].totalVol = 0;

		if(cdn[i].upTotalVol > 0)
			samplesUp++;

		cdndata.upTotalVol += cdn[i].upTotalVol;

		if(cdn[i].upTotalVol > cdndata.peakUpTotalVol)
			cdndata.peakUpTotalVol = cdn[i].upTotalVol;
		cdn[i].upTotalVol = 0;

		if(cdn[i].dnTotalVol > 0)
			samplesDn++;

		cdndata.dnTotalVol += cdn[i].dnTotalVol;

		if(cdn[i].dnTotalVol > cdndata.peakDnTotalVol)
			cdndata.peakDnTotalVol = cdn[i].dnTotalVol;
		cdn[i].dnTotalVol = 0;
	}

	if(samplesTotal > 0)
	{ cdndata.avgTotalBw 	= (cdndata.totalVol * 8) / samplesTotal; }

	if(samplesUp > 0)
	{ cdndata.avgUpBw 		= (cdndata.upTotalVol * 8) / samplesUp; }
	if(samplesDn > 0)
	{ cdndata.avgDnBw 		= (cdndata.dnTotalVol * 8) / samplesDn; }

	return cdndata;
}
