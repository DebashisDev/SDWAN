#ifndef BUILTIN_GETOPT_H
#define BUILTIN_GETOPT_H


extern "C" DLLENTRY int getopt (int argc, char** argv, char* opts);
extern "C" DLLENTRY char *optarg;
extern "C" DLLENTRY int optind;
extern "C" DLLENTRY int opterr;
extern "C" DLLENTRY int optpos;
extern "C" DLLENTRY int optproblem;
extern "C" DLLENTRY char *optprogname;
extern "C" DLLENTRY int opteof;

#endif


