/* My bet is this was written by Chris Torek.
   I reformatted and ansidecl-ized it, and tweaked it a little.  */

#include <ansidecl.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>

struct ltest
  {
    CONST char *str;		/* Convert this.  */
    unsigned long int expect;	/* To get this.  */
    int base;			/* Use this base.  */
    char left;			/* With this left over.  */
    int err;			/* And this in errno.  */
  };
static CONST struct ltest tests[] =
  {
#if ~0UL == 0xffffffff
    /* First, signed numbers.  */
    { "   -17",		-17,		0,	0,	0 },
    { " +0x123fg",	0x123f,		0,	'g',	0 },
    { "2147483647",	2147483647,	0,	0,	0 },
    { "2147483648",	2147483647,	0,	0,	ERANGE },
    { "214748364888",	2147483647,	0,	0,	ERANGE },
    { "2147483650",	2147483647,	0,	0,	ERANGE },
    { "-2147483649",	-2147483648,	0,	0,	ERANGE },
    { "-2147483648",	-2147483648,	0,	0,	0 },
    { "0123",		0123,		0,	0,	0 },
    { "0x1122334455z",	2147483647,	16,	'z',	ERANGE },
    { "0x0xc",		0,		0,	'x',	0 },
    { "yz!",		34*36+35,	36,	'!',	0 },
    { NULL,		0,		0,	0,	0 },

    /* Then unsigned.  */
    { "  0",		0,		0,	0,	0 },
    { "0xffffffffg",	0xffffffff,	0,	'g',	0 },
    { "0xf1f2f3f4f5",	0xffffffff,	0,	0,	ERANGE },
    { "-0x123456789",	0xffffffff,	0,	0,	ERANGE },
    { "-0xfedcba98",	-0xfedcba98,	0,	0,	0 },
    { NULL,		0,		0,	0,	0 },
#else
    /* assume 64 bit long... */

    /* First, signed numbers.  */
    { "   -17",			-17,		0,	0,	0 },
    { " +0x123fg",		0x123f,		0,	'g',	0 },
    { "2147483647",		2147483647,	0,	0,	0 },
    { "9223372036854775807",	9223372036854775807,	0,	0,	0 },
    { "9223372036854775808",	9223372036854775807,	0,	0,	ERANGE },
    { "922337203685477580777",	9223372036854775807,	0,	0,	ERANGE },
    { "9223372036854775810",	9223372036854775807,	0,	0,	ERANGE },
    { "-2147483648",		-2147483648,	0,	0,	0 },
    { "-9223372036854775808",	-9223372036854775808,	0,	0,	0 },
    { "-9223372036854775809",	-9223372036854775808,	0,	0,	ERANGE },
    { "0123",		0123,		0,	0,	0 },
    { "0x112233445566778899z",	9223372036854775807,	16,	'z',	ERANGE },
    { "0x0xc",		0,		0,	'x',	0 },
    { "yz!",		34*36+35,	36,	'!',	0 },
    { NULL,		0,		0,	0,	0 },

    /* Then unsigned.  */
    { "  0",		0,		0,	0,	0 },
    { "0xffffffffg",	0xffffffff,	0,	'g',	0 },
    { "0xffffffffffffffffg",	0xffffffffffffffff,	0,	'g',	0 },
    { "0xf1f2f3f4f5f6f7f8f9",	0xffffffffffffffff,	0,	0,	ERANGE },
    { "-0x123456789abcdef01",	0xffffffffffffffff,	0,	0,	ERANGE },
    { "-0xfedcba987654321",	-0xfedcba987654321,	0,	0,	0 },
    { NULL,		0,		0,	0,	0 },
#endif
  };

static void EXFUN(expand, (char *dst, int c));

int
DEFUN_VOID(main)
{
  register CONST struct ltest *lt;
  char *ep;
  int status = 0;

  for (lt = tests; lt->str != NULL; ++lt)
    {
      register long int l;

      errno = 0;
      l = strtol(lt->str, &ep, lt->base);
      printf("strtol(\"%s\", , %d) test %u",
	     lt->str, lt->base, (unsigned int) (lt - tests));
      if (l == (long int) lt->expect && *ep == lt->left && errno == lt->err)
	puts("\tOK");
      else
	{
	  puts("\tBAD");
	  if (l != (long int) lt->expect)
	    printf("  returns %ld, expected %ld\n",
		   l, (long int) lt->expect);
	  if (lt->left != *ep)
	    {
	      char exp1[5], exp2[5];
	      expand(exp1, *ep);
	      expand(exp2, lt->left);
	      printf("  leaves '%s', expected '%s'\n", exp1, exp2);
	    }
	  if (errno != lt->err)
	    printf("  errno %d (%s)  instead of %d (%s)\n",
		   errno, strerror(errno), lt->err, strerror(lt->err));
	  status = 1;
	}
    }

  for (++lt; lt->str != NULL; lt++)
    {
      register unsigned long int ul;

      errno = 0;
      ul = strtoul(lt->str, &ep, lt->base);
      printf("strtoul(\"%s\", , %d) test %u",
	     lt->str, lt->base, (unsigned int) (lt - tests));
      if (ul == lt->expect && *ep == lt->left && errno == lt->err)
	puts("\tOK");
      else
	{
	  puts("\tBAD");
	  if (ul != lt->expect)
	    printf("  returns %lu, expected %lu\n",
		   ul, lt->expect);
	  if (lt->left != *ep)
	    {
	      char exp1[5], exp2[5];
	      expand(exp1, *ep);
	      expand(exp2, lt->left);
	      printf("  leaves '%s', expected '%s'\n", exp1, exp2);
	    }
	  if (errno != lt->err)
	    printf("  errno %d (%s) instead of %d (%s)\n",
		   errno, strerror(errno), lt->err, strerror(lt->err));
	  status = 1;
	}
    }

  exit(status ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void
DEFUN(expand, (dst, c), register char *dst AND register int c)
{
  if (isprint(c))
    {
      dst[0] = c;
      dst[1] = '\0';
    }
  else
    (void) sprintf(dst, "%#.3o", (unsigned int) c);
}
