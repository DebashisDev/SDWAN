/*
 * BaseConfig.h
 *
 *  Created on: 29-Jan-2016
 *      Author: Debashis
 */

#ifndef SRC_BASECONFIG_H_
#define SRC_BASECONFIG_H_

#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "SpectaTypedef.h"

using namespace std;

class BaseConfig
{
	protected:
		string _name;
		inline string name() const {return _name;}
		int _thisLogLevel;
		inline int thisLogLevel () const {return _thisLogLevel;}
		void setLogLevel (int level) {_thisLogLevel = level;}
};

#endif /* SRC_BASECONFIG_H_ */
