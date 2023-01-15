#ifndef __multiplatform_h__
#define __multiplatform_h__

// NULL redefinition for HP-UX
#ifdef HPUX
#  ifdef NULL
#    undef NULL
#  endif
#  define NULL 0x0
#endif

// builtin getopt()
#if (defined __CYGWIN__)
#  define _USE_SYSTEM_GETOPT
#elif (defined _WIN32) || (defined WIN32)
#  define _USE_BUILTIN_GETOPT
#endif


#if (defined _WIN32) || (defined WIN32) || (defined __CYGWIN__)
#  ifdef BUILD_DLL
#    define DLLENTRY __declspec(dllexport)
#  else
#    define DLLENTRY __declspec(dllimport)
#  endif
#  ifdef BUILD_PGIN
#    define PGENTRY __declspec(dllexport)
#  else
#    define PGENTRY
#  endif
#else
#  define DLLENTRY
#  define PGENTRY
#endif


// compiler techniques
#ifdef HPUX
#  define PGIN_USE_EH_MARSHALL
#endif

namespace std
{
};

#endif
