#ifndef _LIBINTL_H
#include <intl/libintl.h>

/* Now define the internal interfaces.  */
extern char *__gettext (__const char *__msgid) __THROW;
extern char *__dgettext (__const char *__domainname,
			 __const char *__msgid) __THROW;
extern char *__dcgettext (__const char *__domainname,
			  __const char *__msgid, int __category) __THROW;
extern char *__textdomain (__const char *__domainname) __THROW;
extern char *__bindtextdomain (__const char *__domainname,
			       __const char *__dirname) __THROW;
extern const char _libc_intl_domainname[];

/* Define the macros `_' and `N_' for conveniently marking translatable
   strings in the libc source code.  We have to make sure we get the
   correct definitions so we undefine the macros first.  */

# undef N_
# define N_(msgid)	msgid

# undef _
# ifdef dgettext
/* This is defined as an optimizing macro, so use it.  */
#  define _(msgid)	dgettext (_libc_intl_domainname, (msgid))
# else
/* Be sure to use only the __ name when `dgettext' is a plain function
   instead of an optimizing macro.  */
#  define _(msgid)	__dgettext (_libc_intl_domainname, (msgid))
# endif

#endif
