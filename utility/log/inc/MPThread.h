#ifndef __MPThread_h__
#define __MPThread_h__

#include <stdexcept>

#include "multiplatform.h"
using namespace std;


#include <pthread.h>

#if (!defined WIN32) && (!defined _WIN32)
#  include <signal.h>


// Signal SIGALARM is not blocked since Wavecom plugins uses it.
// Note that another (working) possibility is to block it (in following macro) and
// set it to unblocked in the serialize/deserialize functions of the Wavecom plugin
#  define MPTHREAD_BLOCK_SIGNALS_ON_SET(sig) \
sigemptyset (&sig);\
sigaddset (&sig, SIGINT);\
sigaddset (&sig, SIGKILL);\
sigaddset (&sig, SIGHUP);\
sigaddset (&sig, SIGTERM);\
sigaddset (&sig, SIGALRM);\
sigaddset (&sig, SIGPIPE);\
pthread_sigmask (SIG_SETMASK, &sig, NULL);

#  define MPTHREAD_BLOCK_SIGNALS {sigset_t sig;MPTHREAD_BLOCK_SIGNALS_ON_SET(sig);}
#else
#  define MPTHREAD_BLOCK_SIGNALS
#  define MPTHREAD_BLOCK_SIGNALS_ON_SET
#endif

#define MP_THREAD_STACK_SIZE_DEF 2*1024*1024


namespace MP
{
  class DLLENTRY Thread
  {
  public:
    Thread ();
    virtual ~Thread ();

    void run (void*(*)(void*),
              void* iParam = NULL,
              unsigned iStackSize = MP_THREAD_STACK_SIZE_DEF)
    throw (runtime_error);

    void cancel () throw (runtime_error);
    void safeCancel ();
    inline unsigned id () const { return (unsigned)_thread; }
    inline static unsigned self () {return (unsigned)pthread_self ();}

    static void join (Thread& iThr);

    static void rund (void*(*)(void*),
                      void* iParam = NULL,
                      unsigned iStackSize = MP_THREAD_STACK_SIZE_DEF)
    throw (runtime_error);

  private:
    pthread_t _thread;
  };
};

using namespace MP;
#endif
