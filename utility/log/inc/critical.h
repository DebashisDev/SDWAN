#ifndef __critical_h__
#define __critical_h__

#include <stdio.h>
#include <errno.h>

#include <stdexcept>

#include "multiplatform.h"
using namespace std;


#if defined __CYGWIN__ || defined sun
#else
#  define __PTH_HAS_RWLOCK__
#endif


// #define __CRITICAL_USE_PAC

#ifndef _MT_SAFE
//#  define pthread_mutex_t     int
//#  define pthread_mutex_init(x,y)
//#  define pthread_mutex_destroy(x)
//#  define pthread_mutex_lock(x)
//#  define pthread_mutex_trylock(x)    1
//#  define pthread_mutex_unlock(x)
//#  define pthread_rwlock_t      int
//#  define pthread_rwlock_init(x,y)
//#  define pthread_rwlock_destroy(x)
//#  define pthread_rwlock_rdlock(x)
//#  define pthread_rwlock_wrlock(x)
//#  define pthread_rwlock_tryrdlock(x) 1
//#  define pthread_rwlock_trywrlock(x) 1
//#  define pthread_rwlock_unlock(x)
//#  define pthread_cond_t     int
//#  define pthread_cond_init(x,y)
//#  define pthread_cond_destroy(x)
//#  define pthread_cond_signal(x)
//#  define pthread_cond_broadcast(x)
//#  define pthread_cond_wait(x,y)      1
//#  define pthread_cond_timedwait(x,y,z) 1
//#  define pthread_cleanup_push(x,y)
//#  define pthread_cleanup_pop(x)

#  include <time.h>
//#  define ETIMEDOUT 999
#  if !defined WIN32 && !defined WIN32
/*struct timespec {
  long tv_sec;
  long tv_nsec;
};*/
#  endif
#else
// define C++ - style  cleanup
#  define __CLEANUP_CXX
#  include <pthread.h>
#endif


#ifdef __PTH_HAS_RWLOCK__
#else
#  define pthread_rwlock_t          pthread_mutex_t
#  define pthread_rwlock_init       pthread_mutex_init
#  define pthread_rwlock_destroy    pthread_mutex_destroy
#  define pthread_rwlock_rdlock     pthread_mutex_lock
#  define pthread_rwlock_wrlock     pthread_mutex_lock
#  define pthread_rwlock_tryrdlock  pthread_mutex_trylock
#  define pthread_rwlock_trywrlock  pthread_mutex_trylock
#  define pthread_rwlock_unlock     pthread_mutex_unlock
#endif


namespace critical
{
  /////////////////////////////
  class mutex
  /////////////////////////////
  {
  public:
    enum type {Default, Recursive};

    mutex (type t = Default);
    ~mutex ();

    inline void lock ()
    {
      pthread_mutex_lock (&_lock);
      _who = pthread_self ();
    }

    inline void trylock ()
    throw (runtime_error)
    {
      if (pthread_mutex_trylock (&_lock) == EBUSY)
      {
        throw runtime_error ("cannot lock: already locked");
      }

      _who = pthread_self ();
    }

    inline void unlock ()
    {
      _who = 0;
      pthread_mutex_unlock (&_lock);
    }

    static void cunlock (void* iThis);

  protected:
    pthread_mutex_t  _lock;
    pthread_t _who;
  };


  //////////////////////////////
  template <typename T>
  class mutexed
    : public mutex
  //////////////////////////////
  {
    public:
    mutexed (type t = Default) : mutex (t) {}
    mutexed (const T& iData, type t = Default) : mutex (t), _data (iData) {}
    mutexed (mutexed<T>& iData, type t = Default) : mutex (t) {_data = iData ();}
    mutexed (const mutexed<T>& iData, type t = Default) : mutex (t) {_data = ((mutexed<T>&)(iData)) ();}
    ~mutexed () {}

    inline T& operator () ()
    {
      lock ();
      T& d = _data;
      unlock ();

      return d;
    }

    inline void operator () (const T& iData)
    {
      lock ();
      _data = iData;
      unlock ();
    }

    inline T&     data ()   {return _data;}
    inline const T& data () const {return _data;}
    inline T* operator -> () {return (T*)(&_data);}

  private:
    T _data;
  };


  /////////////////////////
  class rwlock
  /////////////////////////
  {
  public:
    rwlock ();
    ~rwlock ();

    inline void rdlock ()
    {
      pthread_rwlock_rdlock (&_lock);
      _who = pthread_self ();
    }

    inline void tryrdlock ()
    throw (runtime_error)
    {
      if (pthread_rwlock_tryrdlock (&_lock) == EBUSY)
      {
        throw runtime_error (string ("cannot rdlock: already locked"));
      }

      _who = pthread_self ();
    }

    inline void wrlock ()
    {
      pthread_rwlock_wrlock (&_lock);
      _who = pthread_self ();
    }

    inline void trywrlock ()
    throw (runtime_error)
    {
      if (pthread_rwlock_trywrlock (&_lock) == EBUSY)
      {
        throw runtime_error (string ("cannot wrlock: already locked"));
      }

      _who = pthread_self ();
    }

    inline void unlock ()
    {
      _who = 0;
      pthread_rwlock_unlock (&_lock);
    }

    static void cunlock (void* iThis);

  private:
    pthread_rwlock_t _lock;
    pthread_t _who;
  };


  /////////////////////////////
  template <typename T>
  class rwlocked
    : public rwlock
  /////////////////////////////
  {
    public:
    rwlocked () {}
    rwlocked (const T& iData) : _data (iData) {}
    rwlocked (rwlocked<T>& iData) {_data = iData ();}
    ~rwlocked () {}

    inline T& operator () ()
    {
      rdlock ();
      T& d = _data;
      unlock ();

      return d;
    }

    inline void operator () (const T& iData)
    {
      wrlock ();
      _data = iData;
      unlock ();
    }

    inline T&     data ()   {return _data;}
    inline const T& data () const {return _data;}
    inline T* operator -> () {return (T*)(&_data);}

  private:
    T _data;
  };


  ////////////////////////////////
  class waitlock
    : public mutex
  ////////////////////////////////
  {
    public:
    waitlock ();
    ~waitlock ();

    //* consumer
    void wait    (int iWait = -1, unsigned iWaitUsec = 0) throw (runtime_error);
    bool wait_nx (int iWait = -1, unsigned iWaitUsec = 0);

    void waitLocked    (int iWait = -1, unsigned iWaitUsec = 0) throw (runtime_error);
    bool waitLocked_nx (int iWait = -1, unsigned iWaitUsec = 0);

    //* producer
    void notify (bool iBroadcast = false);

  private:
    pthread_cond_t _waitCond;
  };


  //////////////////////////////
  template <typename T>
  class waitlocked
    : public waitlock
  //////////////////////////////
  {
    public:
    waitlocked () {}
    waitlocked (const T& iData) : _data (iData) {}
    waitlocked (waitlocked<T>& iData) : waitlock () {_data = iData ();}
    waitlocked (const waitlocked<T>& iData) : waitlock () {_data = ((waitlocked<T>&)(iData)) ();}
    ~waitlocked () {}

    inline T& operator () ()
    {
      lock ();
      T& d = _data;
      unlock ();

      return d;
    }

    inline void operator () (const T& iData)
    {
      lock ();
      _data = iData;
      unlock ();
      notify ();
    }

    inline T&     data ()   {return _data;}
    inline const T& data () const {return _data;}
    inline T* operator -> () {return (T*)(&_data);}

  private:
    T _data;
  };


  /**
    The creation of one of this locks an object; it will be
    unlocked upon destruction. Quite useful to save try-catch
    blocks when locking code that could throw exceptions
  */
  /////////////////////////
  template<typename T>
  class locker
  /////////////////////////
  {
    public:
    locker  (T* d) : _d (d)  {_d->lock ();}
    locker  (T& d) : _d (&d) {_d->lock ();}
    ~locker ()               {_d->unlock ();}

    private:
      T* _d;
  };


  /////////////////////////
  template<typename T>
  class trylocker
  /////////////////////////
  {
    public:
    trylocker  (T* d) throw (runtime_error) : _d (d)  {_d->trylock ();}
    trylocker  (T& d) throw (runtime_error) : _d (&d) {_d->trylock ();}
    ~trylocker ()                                     {_d->unlock ();}

    private:
      T* _d;
  };


  ////////////////////////////
  template<typename T>
  class rdlocker
  ////////////////////////////
  {
    public:
    rdlocker  (T* d) : _d (d)  {_d->rdlock ();}
    rdlocker  (T& d) : _d (&d) {_d->rdlock ();}
    ~rdlocker ()               {_d->unlock ();}

    private:
      T* _d;
  };


  ////////////////////////
  template<typename T>
  class tryrdlocker
  ////////////////////////
  {
    public:
    tryrdlocker  (T* d) throw (runtime_error) : _d (d)  {_d->tryrdlock ();}
    tryrdlocker  (T& d) throw (runtime_error) : _d (&d) {_d->tryrdlock ();}
    ~tryrdlocker ()                                     {_d->unlock ();}

    private:
      T* _d;
  };


  /////////////////////////
  template<typename T>
  class wrlocker
  /////////////////////////
  {
    public:
    wrlocker  (T* d) : _d (d)  {_d->wrlock ();}
    wrlocker  (T& d) : _d (&d) {_d->wrlock ();}
    ~wrlocker ()               {_d->unlock ();}

    private:
      T* _d;
  };

  ///////////////////////////
  template<typename T>
  class trywrlocker
  ///////////////////////////
  {
    public:
    trywrlocker  (T* d) throw (runtime_error) : _d (d)  {_d->trywrlock ();}
    trywrlocker  (T& d) throw (runtime_error) : _d (&d) {_d->trywrlock ();}
    ~trywrlocker ()                                     {_d->unlock ();}

    private:
      T* _d;
  };


  class AutoCleanup
  {
  public:
    AutoCleanup (void (*routine) (void *),void *arg);
    ~AutoCleanup ();

    inline void done () {_done = true;}

    private:
    bool _done;
    void (*_routine) (void *);
    void *_arg;
  };
};


#define Critical_lockThis(T)      {critical::locker<T >      cr_lock (this);
#define Critical_trylockThis(T)   {critical::trylocker<T >   cr_lock (this);

#define Critical_rdlockThis(T)    {critical::rdlocker<T >    cr_lock (this);
#define Critical_tryrdlockThis(T) {critical::tryrdlocker<T > cr_lock (this);

#define Critical_wrlockThis(T)    {critical::wrlocker<T >    cr_lock (this);
#define Critical_trywrlockThis(T) {critical::trywrlocker<T > cr_lock (this);

#define Critical_lock(T,o)        {critical::locker<T >      cr_lock (o);
#define Critical_trylock(T,o)     {critical::trylocker<T >   cr_lock (o);

#define Critical_rdlock(T,o)      {critical::rdlocker<T >    cr_lock (o);
#define Critical_tryrdlock(T,o)   {critical::tryrdlocker<T > cr_lock (o);

#define Critical_wrlock(T,o)      {critical::wrlocker<T >    cr_lock (o);
#define Critical_trywrlock(T,o)   {critical::trywrlocker<T > cr_lock (o);

#define Critical_unlock           }

#define Critical_pushCleanup(T,o)   {
#define Critical_pushCleanup_m(m,o) {
#define Critical_popCleanup         }



#endif
