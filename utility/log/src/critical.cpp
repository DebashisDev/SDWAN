#include "critical.h"

#include <string>
#include <iostream>
using namespace std;

#include <sys/time.h>


////////////////////////////////////
critical::mutex::mutex (critical::mutex::type t)
////////////////////////////////////
  : _who (0)
{
  if (t == Default)
  {
    pthread_mutex_init (&_lock, NULL);
  }
  else
  {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init (&attr);
    pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init (&_lock, &attr);
    pthread_mutexattr_destroy (&attr);
  }
}


////////////////////////////////////
critical::mutex::~mutex ()
////////////////////////////////////
{
  pthread_mutex_destroy (&_lock);
}


////////////////////////////////////
void
critical::mutex::cunlock (void* iThis)
////////////////////////////////////
{
  ((mutex*)(iThis))->unlock ();
}


////////////////////////////////////
critical::rwlock::rwlock ()
////////////////////////////////////
  : _who (0)
{
  pthread_rwlock_init (&_lock, NULL);
}


////////////////////////////////////
critical::rwlock::~rwlock ()
////////////////////////////////////
{
  pthread_rwlock_destroy (&_lock);
}


////////////////////////////////////
void
critical::rwlock::cunlock (void* iThis)
////////////////////////////////////
{
  ((rwlock*)(iThis))->unlock ();
}


////////////////////////////////////
critical::waitlock::waitlock ()
////////////////////////////////////
{
  pthread_cond_init (&_waitCond, NULL);
}


////////////////////////////////////
critical::waitlock::~waitlock ()
////////////////////////////////////
{
  pthread_cond_destroy (&_waitCond);
}


////////////////////////////////////
void
critical::waitlock::wait (int iWait, unsigned iWaitUSec)
throw (runtime_error)
////////////////////////////////////
{
  pthread_mutex_lock (&_lock);
  critical::AutoCleanup ac (critical::mutex::cunlock, this);

  if (iWait == -1)
  {
    while (pthread_cond_wait (&_waitCond, &_lock) != 0) {}
  }
  else
  {
    struct timeval tv;
    gettimeofday (&tv, NULL);

    struct timespec timeout;
    timeout.tv_sec = tv.tv_sec + iWait;
    timeout.tv_nsec = (tv.tv_usec  + iWaitUSec) * 1000;

    if (timeout.tv_nsec > 1000000000)
    {
      timeout.tv_sec += timeout.tv_nsec / 1000000000;
      timeout.tv_nsec %= 1000000000;
    }

    if (pthread_cond_timedwait (&_waitCond, &_lock, &timeout))
    {
      char b [200];
      sprintf (b, "wait of %d secs expired", iWait);
      pthread_mutex_unlock (&_lock);
      ac.done ();
      throw runtime_error (b);
    }
  }

  ac.done ();
  pthread_mutex_unlock (&_lock);
}


////////////////////////////////////
bool
critical::waitlock::wait_nx (int iWait, unsigned iWaitUSec)
////////////////////////////////////
{
  pthread_mutex_lock (&_lock);
  critical::AutoCleanup ac (critical::mutex::cunlock, this);

  if (iWait == -1)
  {
    while (pthread_cond_wait (&_waitCond, &_lock) != 0) {}
  }
  else
  {
    struct timeval tv;
    gettimeofday (&tv, NULL);

    struct timespec timeout;
    timeout.tv_sec = tv.tv_sec + iWait;
    timeout.tv_nsec = (tv.tv_usec  + iWaitUSec) * 1000;

    if (timeout.tv_nsec > 1000000000)
    {
      timeout.tv_sec += timeout.tv_nsec / 1000000000;
      timeout.tv_nsec %= 1000000000;
    }

    if (pthread_cond_timedwait (&_waitCond, &_lock, &timeout))
    {
      ac.done ();
      pthread_mutex_unlock (&_lock);
      return true;
    }
  }

  ac.done ();
  pthread_mutex_unlock (&_lock);

  return false;
}


////////////////////////////////////
void
critical::waitlock::waitLocked (int iWait, unsigned iWaitUSec)
throw (runtime_error)
////////////////////////////////////
{
  critical::AutoCleanup ac (critical::mutex::cunlock, this);

  if (iWait == -1)
  {
    while (pthread_cond_wait (&_waitCond, &_lock) != 0) {}
  }
  else
  {
    struct timeval tv;
    gettimeofday (&tv, NULL);

    struct timespec timeout;
    timeout.tv_sec = tv.tv_sec + iWait;
    timeout.tv_nsec = (tv.tv_usec  + iWaitUSec) * 1000;

    if (timeout.tv_nsec > 1000000000)
    {
      timeout.tv_sec += timeout.tv_nsec / 1000000000;
      timeout.tv_nsec %= 1000000000;
    }

    if (pthread_cond_timedwait (&_waitCond, &_lock, &timeout))
    {
      char b [200];
      sprintf (b, "wait of %d secs expired", iWait);
      ac.done ();
      throw runtime_error (b);
    }
  }

  ac.done ();
}


////////////////////////////////////
bool
critical::waitlock::waitLocked_nx (int iWait, unsigned iWaitUSec)
////////////////////////////////////
{
  critical::AutoCleanup ac (critical::mutex::cunlock, this);

  if (iWait == -1)
  {
    while (pthread_cond_wait (&_waitCond, &_lock) != 0) {}
    ac.done ();
    return false;
  }
  else
  {
    struct timeval tv;
    gettimeofday (&tv, NULL);

    struct timespec timeout;
    timeout.tv_sec = tv.tv_sec + iWait;
    timeout.tv_nsec = (tv.tv_usec  + iWaitUSec) * 1000;

    if (timeout.tv_nsec > 1000000000)
    {
      timeout.tv_sec += timeout.tv_nsec / 1000000000;
      timeout.tv_nsec %= 1000000000;
    }

    if (pthread_cond_timedwait (&_waitCond, &_lock, &timeout))
    {
      ac.done ();
      return true;
    }
    else
    {
      ac.done ();
      return false;
    }
  }
}


////////////////////////////////////
void
critical::waitlock::notify (bool iBroadcast)
////////////////////////////////////
{
  if (iBroadcast)
  {
    pthread_cond_broadcast (&_waitCond);
  }
  else
  {
    pthread_cond_signal (&_waitCond);
  }
}


/////////////////////////////////
critical::AutoCleanup::AutoCleanup (void (*routine) (void *), void *arg)
/////////////////////////////////
  : _done (false),
    _routine (routine),
    _arg (arg)
{
//  cerr << pthread_self () << ": created AC with routine [" << _routine << "] and arg [" << _arg << "]" << endl;
}


/////////////////////////////////
critical::AutoCleanup::~AutoCleanup ()
/////////////////////////////////
{
//  cerr << pthread_self () << ": destroy AC with done: " << _done << endl;

  if (_done == false)
  {
//    cerr << pthread_self () << ": about to exec routine [" << _routine << "] with arg [" << _arg << "]" << endl;

//    string str;
//    Instrument::dumpStack (str);
//    cerr <<
//      "***********************************************************************************" << endl <<
//      str << endl <<
//      "************************************************************************************" << endl;

    _routine (_arg);
//    cerr << pthread_self () << ": routine exec ok" << endl;
  }
}

