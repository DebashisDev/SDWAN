
#if defined __linux__
#  include <getopt.h>
#elif defined sun
#  include <stdlib.h>
#elif defined HPUX
#  include <unistd.h>
#elif defined _USE_BUILTIN_GETOPT
#  include <mp/builtin_getopt.h>
#else
#  error se necesita un include para getopt()
#endif

