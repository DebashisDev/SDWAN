#ifndef __MP_Sleep_h__
#define __MP_Sleep_h__

#if (defined _WIN32) && (!defined __CYGWIN__)
#  include <windows.h>
#  define MTsleep(x) Sleep(x*1000)
#  define MTusleep(x) Sleep(x/1000)
#else
#  include "critical.h"
#  include "Log.h"
#  define MTsleep(x)  {critical::waitlock wl;wl.wait_nx (x);}

#  define MTusleep(x)  {\
  struct timespec rqt;\
  struct timespec rmt;\
  rqt.tv_sec = ((x) / 1000000);\
  rqt.tv_nsec = ((x) % 1000000)*1000;\
  for(;;)\
  {\
    if (nanosleep (&rqt, &rmt) == 0) break;\
    pthread_testcancel ();\
    rqt.tv_sec = rmt.tv_sec;\
    rqt.tv_nsec = rmt.tv_nsec;\
  }\
}

#endif


#endif
