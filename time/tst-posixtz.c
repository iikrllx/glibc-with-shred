#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct
{
  time_t when;
  const char *tz;
  const char *result;
} tests[] =
{
  { 909312849L, "AEST-10AEDST-11,M10.5.0,M3.5.0",
    "1998/10/25 21:54:09 dst=1 zone=AEDST" },
  { 924864849L, "AEST-10AEDST-11,M10.5.0,M3.5.0",
    "1999/04/23 20:54:09 dst=0 zone=AEST" },
};

int
main (void)
{
  int result = 0;
  int cnt;

  for (cnt = 0; cnt < sizeof (tests) / sizeof (tests[0]); ++cnt)
    {
      char buf[100];
      struct tm *tmp;

      printf ("TZ = \"%s\", time = %ld => ", tests[cnt].tz, tests[cnt].when);
      fflush (stdout);

      setenv ("TZ", tests[cnt].tz, 1);

      tmp = localtime (&tests[cnt].when);

      snprintf (buf, sizeof (buf),
		"%04d/%02d/%02d %02d:%02d:%02d dst=%d zone=%s",
		tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec, tmp->tm_isdst,
		tzname[tmp->tm_isdst ? 1 : 0]);

      fputs (buf, stdout);

      if (strcmp (buf, tests[cnt].result) == 0)
	puts (", OK");
      else
	{
	  result = 1;
	  puts (", FAIL");
	}
    }

  return result;
}
