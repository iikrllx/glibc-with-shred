#include <dlfcn.h>
#include <stdio.h>


extern int test_in_mod1 (void *);
extern int test_in_mod2 (void *);


int
main (int argc, char *argv[])
{
  int (*ifp) (void);
  void *p;
  int result = 0;

  /* Find function `main'.  */
  p = dlsym (RTLD_DEFAULT, "main");
  if (p == NULL)
    {
      printf ("%s: main not found\n", __FILE__);
      result = 1;
    }
  else if (p != (void *) &main)
    {
      printf ("%s: wrong address returned for main\n", __FILE__);
      result = 1;
    }
  else
    printf ("%s: main correctly found\n", __FILE__);

  ifp = dlsym (RTLD_DEFAULT, "found_in_mod1");
  if ((void *) ifp == NULL)
    {
      printf ("%s: found_in_mod1 not found\n", __FILE__);
      result = 1;
    }
  else if (ifp () != 1)
    {
      printf ("%s: wrong address returned for found_in_mod1\n", __FILE__);
      result = 1;
    }
  else
    printf ("%s: found_in_mod1 correctly found\n", __FILE__);

  ifp = dlsym (RTLD_DEFAULT, "found_in_mod2");
  if ((void *) ifp == NULL)
    {
      printf ("%s: found_in_mod2 not found\n", __FILE__);
      result = 1;
    }
  else if (ifp () != 2)
    {
      printf ("%s: wrong address returned for found_in_mod2\n", __FILE__);
      result = 1;
    }
  else
    printf ("%s: found_in_mod2 correctly found\n", __FILE__);

  result |= test_in_mod1 ((void *) &main);

  result |= test_in_mod2 ((void *) &main);

  return result;
}
