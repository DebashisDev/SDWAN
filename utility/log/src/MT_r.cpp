#include "MT_r.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>


string 
safe_strerror (int x) 
{
  string s = strerror (x);
  return s;
}
