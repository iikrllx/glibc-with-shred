#include <stdio.h>
#include <wchar.h>

#define PASSED  0
#define	FAILED  3


#define TEST_FUNCTION do_test ()
static int do_test (void);
#include "../test-skeleton.c"


static int
do_test (void)
{
  FILE *fptr;
  char arg1;
  char arg2;
  int ret1, ret2, result, num;
  int fd;

  fd = create_temp_file ("wrewind.", NULL);
  if (fd == -1)
    return 3;

  ret1 = 0;
  ret2 = 0;

  fptr = fdopen (fd, "w+");
  if (fptr == NULL)
    {
      printf ("Unable to open file.\n");
      return 1;
    }

  if (fwprintf (fptr, L"cderf") <= 0)
    {
      printf ("Unable to write to file with fwprintf().\n");
      fclose (fptr);
      return 2;
    }

  rewind (fptr);
  ret1 = fwscanf (fptr, L"%c%c", &arg1, &arg2);

  rewind (fptr);
  ret2 = fwscanf (fptr, L"%c%n%c", &arg1, &num, &arg2);

  if (arg2 != 'd')
    {
      result = FAILED;
      printf ("rewind after first fwscanf failed\n");
    }
  else
    {
      printf ("Passed\n");
      result = PASSED;
    }


  fclose (fptr);
  return result;
}
