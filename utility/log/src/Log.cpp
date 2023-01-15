
#define _FILE_OFFSET_BITS 64


#include "Log.h"

#include <mp/fstream>

using namespace std;

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "../inc/MPSleep.h"
#include "../inc/MPctime.h"
#include "../inc/StringManip.h"

#ifdef _MT_SAFE
#  define LOCK    _mutex.lock ()
#  define UNLOCK  _mutex.unlock ()
#else
#  define LOCK
#  define UNLOCK
#endif

//#define LOG_NO
//////////////////////
Log* Log::_theLog = NULL;


//////////////////////
Log::Log ()
throw (runtime_error)
//////////////////////
  : _stream (NULL),
    _level (Info),
    _cascade (true),
    _block (false),
    _rotate (true),
    _lastDay (today ())
#ifdef _MT_SAFE
    ,_lastEntryTime (0)
#endif
{

#ifdef _MT_SAFE
#  ifndef LOG_NO

  _flushThr.run (Log::_flush, this);
#  endif
#endif
}


/////////////////////////////////
Log::Log (const string& iName,
          const string& iFile,
          int iLevel,
          bool iCascade)
throw (runtime_error)
/////////////////////////////////
  : _rotate (true),
    _lastDay (today ())
#ifdef _MT_SAFE
	,_lastEntryTime (0)
#endif
{
  _stream = fopen (iFile.c_str (), "ab");

  if (!_stream)
  {
    throw runtime_error (string ("Cannot open log [")
                         + iFile
                         + "]");
  }

  _strIsOwn = true;
  _level = iLevel;
  _block = false;
  _cascade = iCascade;

  // reflex in conf
//  add ("level", level2str (_level));
//  add ("cascade", (_cascade ? "true" : "false"));
//  add ("file", iFile.c_str ());

#ifdef _MT_SAFE
#  ifndef LOG_NO

  _flushThr.run (_flush, this);
#  endif
#endif
}


/////////////////////////////////
Log::Log (const string& iName,
          FILE* oStr,
          int iLevel,
          bool iCascade)
throw (runtime_error)

/////////////////////////////////
  : _lastDay (today ())
#ifdef _MT_SAFE
	,_lastEntryTime (0)
#endif
{
  _stream = oStr;

  _strIsOwn = false;
  _level = iLevel;
  _block = false;
  _cascade = iCascade;
  _rotate = true;

  // reflex in conf
//  add ("level", level2str (_level));
//  add ("cascade", (_cascade ? "true" : "false"));
//  add ("file", "");

#ifdef _MT_SAFE
#  ifndef LOG_NO

  _flushThr.run (_flush, this);
#  endif
#endif
}


///////////////
Log::~Log ()
///////////////
{
#ifdef _MT_SAFE
  try
  {
    _flushThr.cancel ();
    Thread::join (_flushThr);
  }
  catch (...)
  {
  }
#endif

  if (_stream && _strIsOwn)
  {
    fclose (_stream);
  }
}


///////////////////////////////
Log&
Log::theLog ()
throw (runtime_error)
///////////////////////////////
{

  if (_theLog == NULL)
  {
    _theLog = new Log ();
  }

  return *_theLog;
}


///////////////////////////////
void
Log::destroyTheLog ()
///////////////////////////////
{
  if (_theLog != NULL)
  {
    delete _theLog;
    _theLog = NULL;
  }
}


///////////////////////////////
void
Log::open (const string& iFile)
throw (runtime_error)
///////////////////////////////
{
  LOCK;

  if (_stream && _strIsOwn)
  {
    fclose (_stream);
    _stream = NULL;
  }

  if (iFile == "")
  {
    // send log to Valhal
//    modify ("file", "");
    UNLOCK;
    return ;
  }

  if (false/*asBool ("usePIDNaming", false)*/)
  {
    char b [1024];

#if defined _WIN32 || defined WIN32
    sprintf (b, ".%u", (unsigned)(GetCurrentProcessId ()));
#else
    sprintf (b, ".%u", getpid ());
#endif

    _stream = fopen ((iFile + b).c_str (), "ab");
//    modify ("file", iFile.c_str ());
  }
  else
  {
    _stream = fopen (iFile.c_str (), "ab");
//    modify ("file", iFile.c_str ());
  }

  if (!_stream)
  {
    UNLOCK;

    //throw runtime_error (string ("Cannot open log [")
    //       + iFile
    //       + "]");
  }

  _strIsOwn = true;

  UNLOCK;
}


/////////////////////////////////
void
Log::open (FILE* iStr)
/////////////////////////////////
{
  LOCK;

  if (_stream && _strIsOwn)
  {
    fclose (_stream);
  }

  _stream = iStr;
  _strIsOwn = false;

  // reflex in conf
//  modify ("file", "");

  UNLOCK;
}


/////////////////////
void
Log::close ()
/////////////////////
{
  LOCK;

  if (_stream && _strIsOwn)
  {
    fclose (_stream);
  }

  _stream = NULL;
  _strIsOwn = false;

  // reflex in conf
  //modify ("file", "");

  UNLOCK;
}


////////////////
int
Log::level ()
////////////////
{
//  int l;
//  LOCK;
//  l = _level;
//  UNLOCK;
//  return l;
  return _level;
}


////////////////
int
Log::bLevel ()
////////////////
{
  int l;

  LOCK;
  l = _bLevel;
  UNLOCK;

  return l;
}


/////////////////////////////
void
Log::level (int iLevel)
/////////////////////////////
{
  LOCK;
  _level = iLevel;

  // reflex in conf
//  modify ("level", level2str (_level));

  UNLOCK;
}


////////////////////////////////////
void
Log::addLevel (Level iLevel)
////////////////////////////////////
{
  LOCK;
  _level = _level | iLevel;
  UNLOCK;
}


////////////////////////////////
bool
Log::isLevel (int iLevel)
////////////////////////////////
{
  bool b;

  LOCK;
  b = ((_level & iLevel) ? true : false);
  UNLOCK;

  return b;
}


/////////////////
bool
Log::cascade ()
/////////////////
{
  bool b;

  LOCK;
  b = _cascade;
  UNLOCK;

  return b;
}


//////////////////////////
void
Log::cascade (bool iCascade)
//////////////////////////
{
  LOCK;
  _cascade = iCascade;
  //modify ("cascade", _cascade ? "true" : "false");
  UNLOCK;
}


//////////////////////////////////////
void
Log::operator () (Level iLevel,
                  const string& iStr,
                  const string& iScope)
//////////////////////////////////////
{
  operator ()(iLevel, iStr, iScope, level ());
}

//////////////////////////////////////
void
Log::operator () (Level iLevel,
                  const string& iStr,
                  const string& iScope,
                  int iMinLevel)
//////////////////////////////////////
{
#ifdef _MT_SAFE
  _mutex.lock ();

  if (!_stream)
  {
    _mutex.unlock ();
    return ;
  }
#else
  if(!_stream)
  {
	  return;
  }
#endif
  int lvl = iMinLevel;

  if (lvl == -1)
  {
    lvl = _level;
  }

  if (
    ( _cascade && (iLevel >= lvl) ) ||
    ( ((lvl & iLevel) ? true : false) )
  )
  {
    // unit log message
#ifdef _MT_SAFE
    string* str = header (iLevel, iScope);
    str->append (iStr);
    str->append (footer ());

    _strQueue.push (str);
    _lastEntryTime (time (NULL));
#else
    fwrite (iStr.data (), sizeof (string::value_type), iStr.size (), _stream);
    fflush (_stream);
#endif
  }
#ifdef _MT_SAFE
  _mutex.unlock ();
#endif
}


////////////////////////////////////////////
int
Log::str2level (const string& iLvl)
////////////////////////////////////////////
{
  int ret;

  if (iLvl == "none")
  {
    ret = None;
  }
  else if (iLvl == "debug")
  {
    ret = Debug;
  }
  else if (iLvl == "trace")
  {
    ret = Trace;
  }
  else if (iLvl == "info")
  {
    ret = Info;
  }
  else if (iLvl == "warn")
  {
    ret = Warn;
  }
  else if (iLvl == "minor")
  {
    ret = Minor;
  }
  else if (iLvl == "major")
  {
    ret = Major;
  }
  else if (iLvl == "error")
  {
    ret = Error;
  }
  else if (iLvl == "serious_error")
  {
    ret = SeriousError;
  }
  else
  {
    // non valid
    ret = None;
  }

  return ret;
}


////////////////////////////////////////////
const char*
Log::level2str (int iLvl)
////////////////////////////////////////////
{
  switch (iLvl)
  {
    case None:
      return "none";

    case Debug:
      return "debug";

    case Trace:
      return "trace";

    case Info:
      return "info";

    case Warn:
      return "warn";

    case Minor:
      return "minor";

    case Major:
      return "major";

    case Error:
      return "error";

    case SeriousError:
      return "serious_error";

    default:
      return "";
  }
}


/////////////////
string*
Log::header (Level iLevel, const string& iScope)
/////////////////
{
  // extract time
  struct timeval tv;
  gettimeofday (&tv, NULL);


  char tb [80];
  strftime(tb, 80, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));

  //string tb = mp_ctime ();
  //tb [tb.size () - 1] = 0;

  char ts [32];
  //snprintf (ts, 31, "%lu.%03lu", tv.tv_sec, tv.tv_usec / 1000);
  snprintf (ts, 31, ".%03lu", tv.tv_usec / 1000);

#ifdef _MT_SAFE
  string* s = new string;
  string tmp_res;
  s->reserve (1024);
//  s->append ("{thread ");
//  StringManip::itoa (tmp_res, (unsigned long)(pthread_self ()));
//  s->append (tmp_res);
//  s->append ("}{");
//  s->append (tb.c_str ());
//  s->append (" - ");
//  s->append (tb);
//  s->append (ts);
//  s->append ("}{");
//  s->append (level2str (iLevel));
//  s->append ("}{");
//  s->append (iScope);
//  s->append ("}");

    s->append (tmp_res);
    s->append (tb);
    s->append (ts);
    s->append (" [");
    s->append (level2str (iLevel));
    s->append ("] ");
    s->append (iScope);


  return s;
#else
  char buff [2000];
  sprintf (buff, "{%s}{%s}{%s}", tb, level2str (iLevel), iScope.c_str ());
  return buff;
#endif
}


/////////////////
const char*
Log::footer ()
/////////////////
{
  return "\n";
}


//////////////////////////
unsigned
Log::today ()
//////////////////////////
{
  time_t t = time (NULL);

  struct tm ttm;
  localtime_r (&t, &ttm);
  return ttm.tm_mday;
}


#ifdef _MT_SAFE
//////////////////////////
void*
Log::_flush (void* _t)
//////////////////////////
{
  string* msg;
  Log* _this = (Log*)(_t);

  MPTHREAD_BLOCK_SIGNALS;

  while (true)
  {
    // get some stuff: if queue is empty the calling thread will sleep...
    msg = _this->_strQueue.pop ();

    if (msg)
    {
      _this->_mutex.lock ();

      if (_this->_stream)
      {
        fwrite (msg->data (), sizeof (string::value_type), msg->size (), _this->_stream);
        fflush (_this->_stream);
      }

      delete msg;
      _this->_lastEntryTime (time (NULL));

      // do we need to flush?
      if (_this->_rotate && _this->_strIsOwn)
      {
        time_t t = time (NULL);

        struct tm ttm;
        localtime_r (&t, &ttm);

        // rotate logs: check if we just pass midnight
        unsigned thisDay = ttm.tm_mday;

/*        if (_this->_lastDay != thisDay)
        {
          // update state
          _this->_lastDay = thisDay;

          // close file
          fclose (_this->_stream);
          _this->_stream = NULL;

          // rename
          struct tm last_tm;
          time_t tt = t - 86400;
          localtime_r (&tt, &last_tm);

          char newName [500];

          sprintf (newName,
                   "%s.%02u-%02u-%04u",
                   _this->asString ("file").c_str (),
                   last_tm.tm_mday,
                   last_tm.tm_mon + 1,
                   last_tm.tm_year + 1900);

          struct stat st;
          string nname (newName);
          unsigned count = 1;

          while (stat (nname.c_str (), &st) == 0)
          {
            // file already exists! add a prefix
            char b [32];
            sprintf (b, ".remain-%u", count);
            count++;
            nname = string (newName) + b;
          }

          rename (_this->asString ("file").c_str (), nname.c_str ());

          // reopen log
          _this->_stream = fopen (_this->asString ("file").c_str (), "ab");

          // postprocess?
          if (_this->_postProcessRotations != "")
          {
            system ((_this->_postProcessRotations + " " + nname + " &").c_str ());
          }
        }*/
      }

      _this->_mutex.unlock ();
    }
  }

  return NULL;
}

#endif
