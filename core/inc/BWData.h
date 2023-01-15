/*
 * BWData.h
 *
 *  Created on: 27-may-2016
 *      Author: Debashis
 */

#ifndef SRC_BWDATA_H_
#define SRC_BWDATA_H_

#include <stdlib.h>    //malloc
#include <string.h>    //strlen
#include <ctime>
#include "Log.h"
#include "BaseConfig.h"
#include "IPGlobal.h"

#define BW_TIME_INDEX	100

class BWData : public BaseConfig
{
	private:

		uint8_t		isUpDir;
		uint16_t	interfaceId;
		uint16_t	routerId;
		uint16_t	volume;
		uint16_t	curSec;
		uint64_t	bwval;

		bwData 	bw_i_r_t[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][2][BW_TIME_INDEX];
		bwData 	calculateBwData(bwData (&bw)[BW_TIME_INDEX]);
		void 	processBwData(bwData (&bw)[BW_TIME_INDEX]);

	public:
		BWData(uint16_t intfid, uint16_t rid);
		~BWData();

		void updateBWData(uint16_t curMin, MPacket *msgObj);
		void setBWData(uint16_t curMin);
};

#endif /* SRC_BWDATA_H_ */
