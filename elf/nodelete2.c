#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int
main (void)
{
  void *handle = dlopen ("nodel2mod3.so", RTLD_LAZY);
  if (handle == NULL)
    {
      printf ("%s\n", dlerror ());
      exit (1);
    }
  dlclose (handle);
  exit (1);
}
