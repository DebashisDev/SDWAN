#ifndef __Log_h__
#define __Log_h__


#include "multiplatform.h"
#define LOG_BUFFSIZE 10240

#ifndef LOG_NO

#  include <stdio.h>

#  define TheLog(x,y,z) ::Log::theLog()(x,y,z,this->thisLogLevel())
#  define TheLog_nc(x,y,z) ::Log::theLog()(x,y,z)

#    define TheLog_v1(level,env,str,p1) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_v2(level,env,str,p1,p2) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_v3(level,env,str,p1,p2,p3) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_v4(level,env,str,p1,p2,p3,p4) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_v5(level,env,str,p1,p2,p3,p4,p5) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_v6(level,env,str,p1,p2,p3,p4,p5,p6) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5,p6);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,this->thisLogLevel());delete[] bf;}
#    define TheLog_nc_v1(level,env,str,p1) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}
#    define TheLog_nc_v2(level,env,str,p1,p2) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}
#    define TheLog_nc_v3(level,env,str,p1,p2,p3) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}
#    define TheLog_nc_v4(level,env,str,p1,p2,p3,p4) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}
#    define TheLog_nc_v5(level,env,str,p1,p2,p3,p4,p5) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}
#    define TheLog_nc_v6(level,env,str,p1,p2,p3,p4,p5,p6) \
       {char* bf = new char [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5,p6);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env);delete[] bf;}

#else

#  define TheLogGeneral(x,y)
#  define TheLog(x,y,z)

#  define TheLog_v1(level,env,str,p1)
#  define TheLog_v2(level,env,str,p1,p2)
#  define TheLog_v3(level,env,str,p1,p2,p3)
#  define TheLog_v4(level,env,str,p1,p2,p3,p4)
#  define TheLog_v5(level,env,str,p1,p2,p3,p4,p5)
#  define TheLog_v6(level,env,str,p1,p2,p3,p4,p5,p6)

#endif


#define LogDebug(str,n)        TheLog(Log::Debug,str,n)
#define LogTrace(str,n)         TheLog(Log::Trace,str,n)
#define LogNotice(str,n)       TheLog(Log::Notice,str,n)
#define LogWarn(str,n)         TheLog(Log::Warn,str,n)
#define LogMinor(str,n)        TheLog(Log::Minor,str,n)
#define LogMajor(str,n)        TheLog(Log::Major,str,n)
#define LogError(str,n)        TheLog(Log::Error,str,n)
#define LogSeriousError(str,n) TheLog(Log::SeriousError,str,n)

#define LogDebug_v1(n,str,p1)           TheLog_v1(Log::Debug,n,str,p1)
#define LogTrace_v1(n,str,p1)            TheLog_v1(Log::Trace,n,str,p1)
#define LogNotice_v1(n,str,p1)          TheLog_v1(Log::Notice,n,str,p1)
#define LogWarn_v1(n,str,p1)            TheLog_v1(Log::Warn,n,str,p1)
#define LogMinor_v1(n,str,p1)           TheLog_v1(Log::Minor,n,str,p1)
#define LogMajor_v1(n,str,p1)           TheLog_v1(Log::Major,n,str,p1)
#define LogError_v1(n,str,p1)           TheLog_v1(Log::Error,n,str,p1)
#define LogSeriousError_v1(n,str,p1)    TheLog_v1(Log::SeriousError,n,str,p1)

#define LogDebug_nc_v1(n,str,p1)        TheLog_nc_v1(Log::Debug,n,str,p1)
#define LogTrace_nc_v1(n,str,p1)         TheLog_nc_v1(Log::Trace,n,str,p1)
#define LogNotice_nc_v1(n,str,p1)       TheLog_nc_v1(Log::Notice,n,str,p1)
#define LogWarn_nc_v1(n,str,p1)         TheLog_nc_v1(Log::Warn,n,str,p1)
#define LogMinor_nc_v1(n,str,p1)        TheLog_nc_v1(Log::Minor,n,str,p1)
#define LogMajor_nc_v1(n,str,p1)        TheLog_nc_v1(Log::Major,n,str,p1)
#define LogError_nc_v1(n,str,p1)        TheLog_nc_v1(Log::Error,n,str,p1)
#define LogSeriousError_nc_v1(n,str,p1) TheLog_nc_v1(Log::SeriousError,n,str,p1)

#define LogDebug_v2(n,str,p1,p2)           TheLog_v2(Log::Debug,n,str,p1,p2)
#define LogTrace_v2(n,str,p1,p2)            TheLog_v2(Log::Trace,n,str,p1,p2)
#define LogNotice_v2(n,str,p1,p2)          TheLog_v2(Log::Notice,n,str,p1,p2)
#define LogWarn_v2(n,str,p1,p2)            TheLog_v2(Log::Warn,n,str,p1,p2)
#define LogMinor_v2(n,str,p1,p2)           TheLog_v2(Log::Minor,n,str,p1,p2)
#define LogMajor_v2(n,str,p1,p2)           TheLog_v2(Log::Major,n,str,p1,p2)
#define LogError_v2(n,str,p1,p2)           TheLog_v2(Log::Error,n,str,p1,p2)
#define LogSeriousError_v2(n,str,p1,p2)    TheLog_v2(Log::SeriousError,n,str,p1,p2)

#define LogDebug_nc_v2(n,str,p1,p2)        TheLog_nc_v2(Log::Debug,n,str,p1,p2)
#define LogTrace_nc_v2(n,str,p1,p2)         TheLog_nc_v2(Log::Trace,n,str,p1,p2)
#define LogNotice_nc_v2(n,str,p1,p2)       TheLog_nc_v2(Log::Notice,n,str,p1,p2)
#define LogWarn_nc_v2(n,str,p1,p2)         TheLog_nc_v2(Log::Warn,n,str,p1,p2)
#define LogMinor_nc_v2(n,str,p1,p2)        TheLog_nc_v2(Log::Minor,n,str,p1,p2)
#define LogMajor_nc_v2(n,str,p1,p2)        TheLog_nc_v2(Log::Major,n,str,p1,p2)
#define LogError_nc_v2(n,str,p1,p2)        TheLog_nc_v2(Log::Error,n,str,p1,p2)
#define LogSeriousError_nc_v2(n,str,p1,p2) TheLog_nc_v2(Log::SeriousError,n,str,p1,p2)

#define LogDebug_v3(n,str,p1,p2,p3)           TheLog_v3(Log::Debug,n,str,p1,p2,p3)
#define LogTrace_v3(n,str,p1,p2,p3)            TheLog_v3(Log::Trace,n,str,p1,p2,p3)
#define LogNotice_v3(n,str,p1,p2,p3)          TheLog_v3(Log::Notice,n,str,p1,p2,p3)
#define LogWarn_v3(n,str,p1,p2,p3)            TheLog_v3(Log::Warn,n,str,p1,p2,p3)
#define LogMinor_v3(n,str,p1,p2,p3)           TheLog_v3(Log::Minor,n,str,p1,p2,p3)
#define LogMajor_v3(n,str,p1,p2,p3)           TheLog_v3(Log::Major,n,str,p1,p2,p3)
#define LogError_v3(n,str,p1,p2,p3)           TheLog_v3(Log::Error,n,str,p1,p2,p3)
#define LogSeriousError_v3(n,str,p1,p2,p3)    TheLog_v3(Log::SeriousError,n,str,p1,p2,p3)

#define LogDebug_nc_v3(n,str,p1,p2,p3)        TheLog_nc_v3(Log::Debug,n,str,p1,p2,p3)
#define LogTrace_nc_v3(n,str,p1,p2,p3)         TheLog_nc_v3(Log::Trace,n,str,p1,p2,p3)
#define LogNotice_nc_v3(n,str,p1,p2,p3)       TheLog_nc_v3(Log::Notice,n,str,p1,p2,p3)
#define LogWarn_nc_v3(n,str,p1,p2,p3)         TheLog_nc_v3(Log::Warn,n,str,p1,p2,p3)
#define LogMinor_nc_v3(n,str,p1,p2,p3)        TheLog_nc_v3(Log::Minor,n,str,p1,p2,p3)
#define LogMajor_nc_v3(n,str,p1,p2,p3)        TheLog_nc_v3(Log::Major,n,str,p1,p2,p3)
#define LogError_nc_v3(n,str,p1,p2,p3)        TheLog_nc_v3(Log::Error,n,str,p1,p2,p3)
#define LogSeriousError_nc_v3(n,str,p1,p2,p3) TheLog_nc_v3(Log::SeriousError,n,str,p1,p2,p3)

#define LogDebug_v4(n,str,p1,p2,p3,p4)           TheLog_v4(Log::Debug,n,str,p1,p2,p3,p4)
#define LogTrace_v4(n,str,p1,p2,p3,p4)            TheLog_v4(Log::Trace,n,str,p1,p2,p3,p4)
#define LogNotice_v4(n,str,p1,p2,p3,p4)          TheLog_v4(Log::Notice,n,str,p1,p2,p3,p4)
#define LogWarn_v4(n,str,p1,p2,p3,p4)            TheLog_v4(Log::Warn,n,str,p1,p2,p3,p4)
#define LogMinor_v4(n,str,p1,p2,p3,p4)           TheLog_v4(Log::Minor,n,str,p1,p2,p3,p4)
#define LogMajor_v4(n,str,p1,p2,p3,p4)           TheLog_v4(Log::Major,n,str,p1,p2,p3,p4)
#define LogError_v4(n,str,p1,p2,p3,p4)           TheLog_v4(Log::Error,n,str,p1,p2,p3,p4)
#define LogSeriousError_v4(n,str,p1,p2,p3,p4)    TheLog_v4(Log::SeriousError,n,str,p1,p2,p3,p4)

#define LogDebug_nc_v4(n,str,p1,p2,p3,p4)        TheLog_nc_v4(Log::Debug,n,str,p1,p2,p3,p4)
#define LogTrace_nc_v4(n,str,p1,p2,p3,p4)         TheLog_nc_v4(Log::Trace,n,str,p1,p2,p3,p4)
#define LogNotice_nc_v4(n,str,p1,p2,p3,p4)       TheLog_nc_v4(Log::Notice,n,str,p1,p2,p3,p4)
#define LogWarn_nc_v4(n,str,p1,p2,p3,p4)         TheLog_nc_v4(Log::Warn,n,str,p1,p2,p3,p4)
#define LogMinor_nc_v4(n,str,p1,p2,p3,p4)        TheLog_nc_v4(Log::Minor,n,str,p1,p2,p3,p4)
#define LogMajor_nc_v4(n,str,p1,p2,p3,p4)        TheLog_nc_v4(Log::Major,n,str,p1,p2,p3,p4)
#define LogError_nc_v4(n,str,p1,p2,p3,p4)        TheLog_nc_v4(Log::Error,n,str,p1,p2,p3,p4)
#define LogSeriousError_nc_v4(n,str,p1,p2,p3,p4) TheLog_nc_v4(Log::SeriousError,n,str,p1,p2,p3,p4)

#define LogDebug_v5(n,str,p1,p2,p3,p4,p5)           TheLog_v5(Log::Debug,n,str,p1,p2,p3,p4,p5)
#define LogTrace_v5(n,str,p1,p2,p3,p4,p5)            TheLog_v5(Log::Trace,n,str,p1,p2,p3,p4,p5)
#define LogNotice_v5(n,str,p1,p2,p3,p4,p5)          TheLog_v5(Log::Notice,n,str,p1,p2,p3,p4,p5)
#define LogWarn_v5(n,str,p1,p2,p3,p4,p5)            TheLog_v5(Log::Warn,n,str,p1,p2,p3,p4,p5)
#define LogMinor_v5(n,str,p1,p2,p3,p4,p5)           TheLog_v5(Log::Minor,n,str,p1,p2,p3,p4,p5)
#define LogMajor_v5(n,str,p1,p2,p3,p4,p5)           TheLog_v5(Log::Major,n,str,p1,p2,p3,p4,p5)
#define LogError_v5(n,str,p1,p2,p3,p4,p5)           TheLog_v5(Log::Error,n,str,p1,p2,p3,p4,p5)
#define LogSeriousError_v5(n,str,p1,p2,p3,p4,p5)    TheLog_v5(Log::SeriousError,n,str,p1,p2,p3,p4,p5)

#define LogDebug_nc_v5(n,str,p1,p2,p3,p4,p5)        TheLog_nc_v5(Log::Debug,n,str,p1,p2,p3,p4,p5)
#define LogTrace_nc_v5(n,str,p1,p2,p3,p4,p5)         TheLog_nc_v5(Log::Trace,n,str,p1,p2,p3,p4,p5)
#define LogNotice_nc_v5(n,str,p1,p2,p3,p4,p5)       TheLog_nc_v5(Log::Notice,n,str,p1,p2,p3,p4,p5)
#define LogWarn_nc_v5(n,str,p1,p2,p3,p4,p5)         TheLog_nc_v5(Log::Warn,n,str,p1,p2,p3,p4,p5)
#define LogMinor_nc_v5(n,str,p1,p2,p3,p4,p5)        TheLog_nc_v5(Log::Minor,n,str,p1,p2,p3,p4,p5)
#define LogMajor_nc_v5(n,str,p1,p2,p3,p4,p5)        TheLog_nc_v5(Log::Major,n,str,p1,p2,p3,p4,p5)
#define LogError_nc_v5(n,str,p1,p2,p3,p4,p5)        TheLog_nc_v5(Log::Error,n,str,p1,p2,p3,p4,p5)
#define LogSeriousError_nc_v5(n,str,p1,p2,p3,p4,p5) TheLog_nc_v5(Log::SeriousError,n,str,p1,p2,p3,p4,p5)

#define LogDebug_v6(n,str,p1,p2,p3,p4,p5,p6)           TheLog_v5(Log::Debug,n,str,p1,p2,p3,p4,p5,p6)
#define LogTrace_v6(n,str,p1,p2,p3,p4,p5,p6)            TheLog_v5(Log::Trace,n,str,p1,p2,p3,p4,p5,p6)
#define LogNotice_v6(n,str,p1,p2,p3,p4,p5,p6)          TheLog_v5(Log::Notice,n,str,p1,p2,p3,p4,p5,p6)
#define LogWarn_v6(n,str,p1,p2,p3,p4,p5,p6)            TheLog_v5(Log::Warn,n,str,p1,p2,p3,p4,p5,p6)
#define LogMinor_v6(n,str,p1,p2,p3,p4,p5,p6)           TheLog_v5(Log::Minor,n,str,p1,p2,p3,p4,p5,p6)
#define LogMajor_v6(n,str,p1,p2,p3,p4,p5,p6)           TheLog_v5(Log::Major,n,str,p1,p2,p3,p4,p5,p6)
#define LogError_v6(n,str,p1,p2,p3,p4,p5,p6)           TheLog_v5(Log::Error,n,str,p1,p2,p3,p4,p5,p6)
#define LogSeriousError_v6(n,str,p1,p2,p3,p4,p5,p6)    TheLog_v5(Log::SeriousError,n,str,p1,p2,p3,p4,p5,p6)

#define LogDebug_nc_v6(n,str,p1,p2,p3,p4,p5,p6)        TheLog_nc_v6(Log::Debug,n,str,p1,p2,p3,p4,p5,p6)
#define LogTrace_nc_v6(n,str,p1,p2,p3,p4,p5,p6)         TheLog_nc_v6(Log::Trace,n,str,p1,p2,p3,p4,p5,p6)
#define LogNotice_nc_v6(n,str,p1,p2,p3,p4,p5,p6)       TheLog_nc_v6(Log::Notice,n,str,p1,p2,p3,p4,p5,p6)
#define LogWarn_nc_v6(n,str,p1,p2,p3,p4,p5,p6)         TheLog_nc_v6(Log::Warn,n,str,p1,p2,p3,p4,p5,p6)
#define LogMinor_nc_v6(n,str,p1,p2,p3,p4,p5,p6)        TheLog_nc_v6(Log::Minor,n,str,p1,p2,p3,p4,p5,p6)
#define LogMajor_nc_v6(n,str,p1,p2,p3,p4,p5,p6)        TheLog_nc_v6(Log::Major,n,str,p1,p2,p3,p4,p5,p6)
#define LogError_nc_v6(n,str,p1,p2,p3,p4,p5,p6)        TheLog_nc_v6(Log::Error,n,str,p1,p2,p3,p4,p5,p6)
#define LogSeriousError_nc_v6(n,str,p1,p2,p3,p4,p5,p6) TheLog_nc_v6(Log::SeriousError,n,str,p1,p2,p3,p4,p5,p6)

#define IfLogLevelHas(x)  if (\
  ((thisLogLevel () != -1 ) && (thisLogLevel () <= (x))) ||\
  ((thisLogLevel () == -1 ) && (Log::theLog ().level () <= (x))))

#define IfNCLogLevelHas(x)  if (Log::theLog ().level () <= (x))

#ifndef NDEBUG
#  include <stdio.h>

#  define DLogGeneral(x,y) ::Log::theLog()(x,y)
#  define DLog(x,y,z) ::Log::theLog()(x,y,z)

#  define DLog_v1(level,env,str,p1) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}
#  define DLog_v2(level,env,str,p1,p2) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}
#  define DLog_v3(level,env,str,p1,p2,p3) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}
#  define DLog_v4(level,env,str,p1,p2,p3,p4) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}
#  define DLog_v5(level,env,str,p1,p2,p3,p4,p5) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}
#  define DLog_v6(level,env,str,p1,p2,p3,p4,p5,p6) \
   {char bf [LOG_BUFFSIZE];snprintf (bf,LOG_BUFFSIZE,str,p1,p2,p3,p4,p5,p6);bf[LOG_BUFFSIZE-1]=0;::Log::theLog()(level,bf,env,thisLogLevel());}

#else

#  define DLogGeneral(x,y)
#  define DLog(x,y,z)

#  define DLog_v1(level,env,str,p1)
#  define DLog_v2(level,env,str,p1,p2)
#  define DLog_v3(level,env,str,p1,p2,p3)
#  define DLog_v4(level,env,str,p1,p2,p3,p4)
#  define DLog_v5(level,env,str,p1,p2,p3,p4,p5)
#  define DLog_v6(level,env,str,p1,p2,p3,p4,p5,p6)

#endif


#include <stdio.h>
#include <string>
#include <mp/stdexcept>
using namespace std;

//#include <Configurable.h>


#ifdef _MT_SAFE
#  include <SafeQueue.h>
#  include <critical.h>
#  include <MPThread.h>
#endif


/**
   Multithreaded file Logger. Uses a separate thread an a queue for the messages.

   <h3>Configuration map:</h3>
     - <b>usePIDNaming</b> : [<i>bool</i>] [defaults to <i>false</i>] : if true, when opening on a file
     tle PID of the process will be appended to the name as an extension

     - <b>Rotate</b> : [<i>bool</i>] [defaults to <i>false</i>] : if true the logs are rotated every midnight.
     The log contents are stored in a file with the same name with the date appended in a DD-MM-YYYY format

     - <b>PostProcessRotations</b> : [<i>string</i>] [defaults to empty string] : if it is not an empty string
     it will define a binary which will be executed with the name of the just created rotation as the first
     parameter
 */
class DLLENTRY Log
{
public:

  /**
     Log level
  */
  enum Level
  {
    None         = 0,
    Debug        = 1,
    Trace        = 2,
    Info         = 4,
    Warn         = 8,
    Minor        = 16,
    Major        = 32,
    Error        = 64,
    SeriousError = 128
  };

  static int         str2level (const string& iLvl);
  static const char* level2str (int iLvl);

  //* default constructor
  Log () throw (runtime_error);

  Log (const string& i_Name,
       const string& iFile,
       int           iLevel = Warn,
       bool          iCascade = true)
  throw (runtime_error);

  Log (const string& iName,
       FILE*         oStr,
       int           iLevel = Warn,
       bool          iCascade = true)
    throw (runtime_error);

  ~Log ();

  static Log& theLog () throw (runtime_error);
  static void destroyTheLog ();

  void open (const string& iFile) throw (runtime_error);
  void open (FILE* iStr);
  void close ();


  int  level ();
  int  bLevel ();
  void level (int iLevel);
  void addLevel (Level iLevel);
  bool isLevel (int iLevel);
  bool cascade ();
  void cascade (bool iCascade);

  void operator () (Level         iLevel,
                    const string& iStr,
                    const string& iScope);

  void operator () (Level         iLevel,
                    const string& iStr,
                    const string& iScope,
                    int           iMinLevel);

  inline time_t lastEntryTime () {return _lastEntryTime ();}

protected:
  string* header (Level iLevel, const string& iScope);
  inline const char* footer ();

  FILE*    _stream;
  bool     _strIsOwn;
  int      _level;
  int      _bLevel;
  bool     _cascade;
  bool     _block;
  bool     _rotate;
  string   _postProcessRotations;

  //* used for log rotating
  unsigned _lastDay;
  static unsigned today ();

  static Log* _theLog;

#ifdef _MT_SAFE
  //* per-instance mutex
  critical::mutex _mutex;

  //* cola de logs
  SafeQueue<string*> _strQueue;

  //* time of last entry
  critical::rwlocked<time_t> _lastEntryTime;

  //* thread para flush
  Thread _flushThr;

  static void* _flush (void* _t);
#endif
};


#endif
