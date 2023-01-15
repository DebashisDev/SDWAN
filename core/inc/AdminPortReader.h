/*
 * adminPortReader.h
 *
 *  Created on: Aug 7, 2017
 *      Author: Debashis
 */

#ifndef CORE_SRC_ADMINPORTREADER_H_
#define CORE_SRC_ADMINPORTREADER_H_

#include "BaseConfig.h"
#include "IPGlobal.h"
#include "SpectaTypedef.h"
#include "Log.h"
#include "GConfig.h"

class AdminPortReader : public BaseConfig
{
	private:
		ifstream 	fp;
		string 		Key, Value;
		GConfig		*pGConfig;

		void 		*adminZmqContext;
		void 		*adminZmqRequester;
		void 		refreshConfig();
		uint32_t 	ipToLong(char *ip, uint32_t *plong);
		void 		openConfigFile(char *fileName);
		void 		closeConfigFile();

	public:
		AdminPortReader();
		~AdminPortReader();
		void run();
};

#endif /* CORE_SRC_ADMINPORTREADER_H_ */
