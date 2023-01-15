#ifndef __MP_ctime_h__
#define __MP_ctime_h__

#include <time.h>
#include <sys/time.h>
#include <string>

#include "multiplatform.h"
using namespace std;


string
mp_ctime (const time_t* t);

string
mp_ctime ();

int
timeval_substract (struct timeval*       result,
                   const struct timeval* x,
                   struct timeval*       y);

#endif
