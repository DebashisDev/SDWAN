/*
 * BWData.cpp
 *
 *  Created on: 27-May-2016
 *      Author: Debashis
 */

#include "BWData.h"

BWData::BWData(uint16_t intfid, uint16_t rid)
{
	this->_name = "BWData";
	this->setLogLevel(Log::theLog().level());

	this->interfaceId 	= intfid;
	this->routerId 		= rid;
	this->volume 		= 0;
	this->bwval 		= 0;
	this->curSec 		= 0;
	this->isUpDir 		= 0;

	printf("** BWData:: Initialized for Interface [%d]\n", this->interfaceId);
}

BWData::~BWData()
{}

void BWData::updateBWData(uint16_t curMin, MPacket *msgObj)
{
	volume = msgObj->frSize;
	isUpDir = msgObj->direction;
	curSec = msgObj->frTimeEpochSec % 100;

	/* 	Write in curMin index based on Odd or Even min
	**	if curMin = 3, write in _1 if curMin = 4 write in _0
	**	Reading will happen opposite
	*/

	uint16_t t_index = curMin % 2;

	processBwData(bw_i_r_t[interfaceId][routerId][t_index]);
}

void BWData::setBWData(uint16_t curMin)
{
	uint16_t t_index = curMin % 2;
	if(t_index == 0) t_index = 1;
	else if(t_index == 1) t_index = 0;

	bwData bw;

	bw = calculateBwData(bw_i_r_t[interfaceId][routerId][t_index]);

	Global::BW_MBPS_i_r[interfaceId][routerId].Bw = bw.Bw;
	Global::BW_MBPS_i_r[interfaceId][routerId].upBw = bw.upBw;
	Global::BW_MBPS_i_r[interfaceId][routerId].dnBw = bw.dnBw;
	Global::BW_MBPS_i_r[interfaceId][routerId].totalVol = bw.totalVol;
	Global::BW_MBPS_i_r[interfaceId][routerId].upTotalVol = bw.upTotalVol;
	Global::BW_MBPS_i_r[interfaceId][routerId].dnTotalVol = bw.dnTotalVol;
	Global::BW_MBPS_i_r[interfaceId][routerId].peakTotalVol 	= bw.peakTotalVol;
	Global::BW_MBPS_i_r[interfaceId][routerId].peakUpTotalVol = bw.peakUpTotalVol;
	Global::BW_MBPS_i_r[interfaceId][routerId].peakDnTotalVol = bw.peakDnTotalVol;

	Global::BW_MBPS_i_r[interfaceId][routerId].avgTotalBw = bw.avgTotalBw;
	Global::BW_MBPS_i_r[interfaceId][routerId].avgUpBw 	= bw.avgUpBw;
	Global::BW_MBPS_i_r[interfaceId][routerId].avgDnBw 	= bw.avgDnBw;

}

bwData BWData::calculateBwData(bwData (&bw)[BW_TIME_INDEX])
{
	uint32_t samplesTotal 	= 0;
	uint32_t samplesUp 		= 0;
	uint32_t samplesDn 		= 0;
	bwData 	 bwdata;

	bwdata.Bw 			= 0;
	bwdata.upBw 		= 0;
	bwdata.dnBw 		= 0;

	bwdata.totalVol 	= 0;
	bwdata.upTotalVol 	= 0;
	bwdata.dnTotalVol 	= 0;
	bwdata.peakTotalVol = 0;
	bwdata.peakUpTotalVol = 0;
	bwdata.peakDnTotalVol = 0;
	bwdata.avgTotalBw 	= 0;
	bwdata.avgUpBw 		= 0;
	bwdata.avgDnBw 		= 0;


	for(uint16_t i = 0; i < BW_TIME_INDEX; i++)
	{

		if(bw[i].totalVol > 0)
			samplesTotal++;

		bwdata.totalVol += bw[i].totalVol;

		if(bw[i].totalVol > bwdata.peakTotalVol)
			bwdata.peakTotalVol = bw[i].totalVol;
		bw[i].totalVol = 0;

		if(bw[i].upTotalVol > 0)
			samplesUp++;

		bwdata.upTotalVol += bw[i].upTotalVol;

		if(bw[i].upTotalVol > bwdata.peakUpTotalVol)
			bwdata.peakUpTotalVol = bw[i].upTotalVol;
		bw[i].upTotalVol = 0;

		if(bw[i].dnTotalVol > 0)
			samplesDn++;

		bwdata.dnTotalVol += bw[i].dnTotalVol;

		if(bw[i].dnTotalVol > bwdata.peakDnTotalVol)
			bwdata.peakDnTotalVol = bw[i].dnTotalVol;
		bw[i].dnTotalVol = 0;
	}

	if(samplesTotal > 0)
		bwdata.avgTotalBw 	= (bwdata.totalVol * 8) / samplesTotal;

	if(samplesUp > 0)
		bwdata.avgUpBw 		= (bwdata.upTotalVol * 8) / samplesUp;
	if(samplesDn > 0)
		bwdata.avgDnBw 		= (bwdata.dnTotalVol * 8) / samplesDn;

	return bwdata;
}

void BWData::processBwData(bwData (&bw)[BW_TIME_INDEX])
{
	bw[curSec].totalVol += volume;
	if(isUpDir == 1)
		bw[curSec].upTotalVol += volume;
	else if(isUpDir == 2)
		bw[curSec].dnTotalVol += volume;
}

