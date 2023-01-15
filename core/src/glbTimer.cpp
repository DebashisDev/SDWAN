/*
 * glbTimer.cpp
 *
 *  Created on: Feb 6, 2019
 *      Author: Debashis
 */

#include "glbTimer.h"

glbTimer::glbTimer()
{ this->timerReadyState = false; }

glbTimer::~glbTimer()
{}

bool glbTimer::isGlbTimerInitialized()
{ return timerReadyState; }

void glbTimer::run()
{
	struct tm *now_tm;
	timerReadyState = true;

	while(true)
	{
		gettimeofday(&curTime, NULL);
		now_tm = localtime(&curTime.tv_sec);

		Global::CURRENT_EPOCH_SEC 		= curTime.tv_sec;
		Global::CURRENT_EPOCH_MICRO_SEC = curTime.tv_usec;
		Global::CURRENT_EPOCH_MILI_SEC	= ((curTime.tv_sec) * 1000 + (curTime.tv_usec)/1000);
		Global::CURRENT_EPOCH_NANO_SEC	= ((curTime.tv_sec * 1000000 + curTime.tv_usec) * 1000);
		Global::CURRENT_DAY 			= now_tm->tm_mday;
		Global::CURRENT_HOUR 			= now_tm->tm_hour;
		Global::CURRENT_MIN 			= now_tm->tm_min;
		Global::CURRENT_SEC 			= now_tm->tm_sec;
		Global::CURRENT_MONTH 			= 1 + now_tm->tm_mon;
		Global::CURRENT_YEAR 			= 1900 + now_tm->tm_year;
	}
}
