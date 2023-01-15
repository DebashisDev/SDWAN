/*
 * glbTimer.h
 *
 *  Created on: Feb 6, 2019
 *      Author: Debashis
 */

#ifndef CORE_SRC_GLBTIMER_H_
#define CORE_SRC_GLBTIMER_H_

#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "IPGlobal.h"

class glbTimer
{
	public:
		glbTimer();
		~glbTimer();

		void run();
		bool isGlbTimerInitialized();

	private:
		bool 		timerReadyState;
		timeval 	curTime;
};

#endif /* CORE_SRC_GLBTIMER_H_ */
