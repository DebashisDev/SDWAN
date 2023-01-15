#include "MPThread.h"

#include <errno.h>
#include <stdio.h>
#include "Log.h"
#include "MT_r.h"

/////////////////////////////////////
Thread::Thread ()
/////////////////////////////////////
  : _thread (0)
{
}


/////////////////////////////////////
Thread::~Thread ()
/////////////////////////////////////
{
  try
  {
    //@    cancel ();
  }
  catch (runtime_error& e)
  {
  }
}


/////////////////////////////////////
void
Thread::run (void*(*iFunc)(void*), void* iParam, unsigned iStackSize)
throw (runtime_error)
/////////////////////////////////////
{
  pthread_attr_t attr;

  pthread_attr_init (&attr);
  pthread_attr_setstacksize (&attr, iStackSize);

  int res = pthread_create (&_thread, &attr, iFunc, iParam);

  if (res)
  {
    char b [512];
    sprintf (b, "Cannot create Processor thread: %s", safe_strerror (errno).c_str ());
    pthread_attr_destroy (&attr);
    _thread = 0;
    throw runtime_error (b);
  }

  pthread_attr_destroy (&attr);
}


/////////////////////////////////////
void
Thread::rund (void*(*iFunc)(void*), void* iParam, unsigned iStackSize)
throw (runtime_error)
/////////////////////////////////////
{
  pthread_t thread;
  pthread_attr_t attr;

  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize (&attr, iStackSize);

  int res = pthread_create (&thread, &attr, iFunc, iParam);

  if (res)
  {
    char b [512];
    sprintf (b, "Cannot create Processor thread: %s", safe_strerror (errno).c_str ());
    pthread_attr_destroy (&attr);
    throw runtime_error (b);
  }

  pthread_attr_destroy (&attr);
}


/////////////////////////////////////
void
Thread::cancel ()
throw (runtime_error)
/////////////////////////////////////
{
  if (!_thread)
  {
    return;
  }

  if (pthread_cancel (_thread))
  {
    char b [512];
    sprintf (b, "Cannot cancel thread: %s", safe_strerror (errno).c_str ());
    throw runtime_error (b);
  }
//  else
//  {
//    TheLog_nc_v1 (Log::Notice, "MPThread", "Thread %d was cancelled", id ());
//  }
}


/////////////////////////////////////
void
Thread::safeCancel ()
/////////////////////////////////////
{
  if (!_thread)
  {
    return;
  }

  pthread_cancel (_thread);
}


/////////////////////////////////////
void
Thread::join (Thread& iThr)
/////////////////////////////////////
{
//  TheLog_nc_v1 (Log::Debug, "MPThread", "about to join thread %d", (unsigned)(iThr._thread));

  if (!(iThr._thread))
  {
    return;
  }

  if (int ret = pthread_join (iThr._thread, NULL))
  {
    TheLog_nc_v2 (Log::Warn, "MPThread", "Cannot join thread [%d]: %s", (int)(iThr._thread), safe_strerror (ret).c_str ());
  }
  else
  {
//    TheLog_nc_v1 (Log::Debug, "MPThread", "succesful join to thread %d", (unsigned)(iThr._thread));
    iThr._thread = 0;
  }
}
