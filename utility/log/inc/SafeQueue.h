#ifndef __SafeQueue_h__
#define __SafeQueue_h__

#include <stdexcept>
#include <pthread.h>

#include <deque>

#include "multiplatform.h"
using namespace std;


/**
   Implementacion de una cola MT-safe. OBJ ha de implementar:
     -#constructor por defecto - OBJ ()
     -#constructor copia - OBJ (const OBJ&)
     -#operador de asignacion  - OBJ& operator= (const OBJ&)
 */
template<typename OBJ>
class SafeQueue
{
public:

  class TimeOutException : public runtime_error
  {
    public:
      TimeOutException (const char* msg) : runtime_error(msg)
      {
      }
  };

  // created infinite by default
  SafeQueue (int max = -1)
    : _maxSize (max),
      _size (0)
  {
    pthread_mutex_init (&_mutex, NULL);
    pthread_cond_init (&_pushCond, NULL);
  }

  ~SafeQueue ()
  {
    pthread_cond_destroy (&_pushCond);
    pthread_mutex_destroy (&_mutex);
  }

  typedef typename deque<OBJ>::iterator       iterator;
  typedef typename deque<OBJ>::const_iterator const_iterator;

  iterator begin () {return _q.begin ();}
  iterator end ()   {return _q.end ();}

  const_iterator begin () const {return _q.begin ();}
  const_iterator end ()   const {return _q.end ();}

  void lock () {pthread_mutex_lock (&_mutex);}
  void unlock () {pthread_mutex_unlock (&_mutex);}

  void
  push (const OBJ& obj)
  {
    pthread_mutex_lock (&_mutex);

    _q.push_back (obj);
    _size++;

    pthread_cond_broadcast (&_pushCond);
    pthread_mutex_unlock (&_mutex);
  }

  void
  push_nl (const OBJ& obj)
  {
    _q.push_back (obj);
    _size++;

    pthread_cond_broadcast (&_pushCond);
  }


  //* Gets top of the queue and removes it from queue
  OBJ
  pop ()
  {
    OBJ obj;

    pthread_mutex_lock (&_mutex);
    pthread_cleanup_push (SafeQueue::cunlock, this);

    // wait for an element if empty
    while (_q.empty ())
    {
      struct timespec timeout;
      timeout.tv_sec = time (NULL) + 1800;
      timeout.tv_nsec = 0;

      pthread_cond_timedwait (&_pushCond, &_mutex, &timeout);
    }

    obj = _q.front ();
    _q.pop_front ();
    _size--;

    pthread_cleanup_pop (0);
    pthread_mutex_unlock (&_mutex);
    return obj;
  }

  //* Gets top of the queue and removes it from queue if found in less than timeout ms
  OBJ
  pop (long lTime) throw (TimeOutException)
  {
    OBJ obj;
    bool timedOut = false;

    pthread_mutex_lock (&_mutex);
    pthread_cleanup_push (SafeQueue::cunlock, this);

    // wait timeout for an element if empty
    if (_q.empty ())
    {
      struct timespec timeout;
      timeout.tv_sec = time (NULL) + (lTime/1000);
      timeout.tv_nsec = (lTime%1000)*1000;

      pthread_cond_timedwait (&_pushCond, &_mutex, &timeout);
    }

    if (_q.empty () == false)
    {
      obj = _q.front ();
      _q.pop_front ();
      _size--;
    }
    else
    {
      timedOut = true;
    }

    pthread_cleanup_pop (0);

    if( timedOut )
    {
      pthread_mutex_unlock (&_mutex);
      throw TimeOutException("Timed out waiting for pop in SafeQueue");
    }
    else
    {
      //* notify element got
      pthread_mutex_unlock (&_mutex);
      return obj;
    }
  }

  OBJ
  pop_nl ()
  {
    OBJ obj;

    // wait for an element if empty
    while (_q.empty ())
    {
      struct timespec timeout;
      timeout.tv_sec = time (NULL) + 1800;
      timeout.tv_nsec = 0;

      pthread_cond_timedwait (&_pushCond, &_mutex, &timeout);
    }

    obj = _q.front ();
    _q.pop_front ();
    _size--;

    return obj;
  }

  void
  trypop (OBJ& oObj, bool& suceed)
  {
    suceed = false;

    pthread_mutex_lock (&_mutex);
    pthread_cleanup_push (SafeQueue::cunlock, this);

    if (_q.empty ())
    {
      suceed = false;
      pthread_mutex_unlock (&_mutex);
      return;
    }

    // quene is not empty
    oObj = _q.front ();
    _q.pop_front ();
    _size--;
    suceed = true;

    pthread_cleanup_pop (0);
    pthread_mutex_unlock (&_mutex);
    return;
  }

  //* returns top of the queue
  OBJ
  top ()
  {
    OBJ obj;

    pthread_mutex_lock (&_mutex);
    pthread_cleanup_push (SafeQueue::cunlock, this);

    while (_q.empty ())
    {
      struct timespec timeout;
      timeout.tv_sec = time (NULL) + 1800;
      timeout.tv_nsec = 0;

      pthread_cond_timedwait (&_pushCond, &_mutex, &timeout);
    }

    obj = _q.front ();

    pthread_cleanup_pop (0);
    pthread_mutex_unlock (&_mutex);

    return obj;
  }

  //* elementos en la cola
  unsigned size ()
  {
    unsigned val;

//    pthread_mutex_lock (&_mutex);
    val = _size;
//    pthread_mutex_unlock (&_mutex);

    return val;
  }

  unsigned size_nl ()
  {
    return _size;
  }

  //* maximo de elementos en la cola
  unsigned maxSize ()
  {
    unsigned val;

 //   pthread_mutex_lock (&_mutex);
    val = _maxSize;
 //   pthread_mutex_unlock (&_mutex);

    return val;
  }

  //* maximo de elementos en la cola
  void maxSize (unsigned i)
  {
    pthread_mutex_lock (&_mutex);
    _maxSize = i;
    pthread_mutex_unlock (&_mutex);
  }

  //* returns const ptr to element at i
  const OBJ* element (unsigned i)
  {
    OBJ* ref = NULL;

    pthread_mutex_lock (&_mutex);
    pthread_cleanup_push (SafeQueue::cunlock, this);

    if (i < _size)
    {
      ref = &(_q [i]);
    }

    pthread_cleanup_pop (0);
    pthread_mutex_unlock (&_mutex);

    return ref;
  }

  //* clears queue
  void clear ()
  {
    pthread_mutex_lock (&_mutex);

    _q.clear ();
    _size = 0;

    pthread_mutex_unlock (&_mutex);
  }

  void clear_nl ()
  {
    _q.clear ();
    _size = 0;
  }

private:
  deque<OBJ>      _q;
  unsigned        _maxSize;
  pthread_mutex_t _mutex;

  //* cached size, for size() in STL seems to be not O(1)
  unsigned _size;

  //* an element has been pushed
  pthread_cond_t  _pushCond;

public:
  static void cunlock (void* iThis)
  {
    pthread_mutex_unlock (&(((SafeQueue<OBJ>*)(iThis))->_mutex));
  }
};

#endif
