#ifndef _TIME_H
#include <time/time.h>

#ifndef _ISOMAC
# include <bits/types/struct_timeval.h>
# include <bits/types/locale_t.h>
# include <stdbool.h>
# include <time/mktime-internal.h>
# include <endian.h>

extern __typeof (strftime_l) __strftime_l;
libc_hidden_proto (__strftime_l)
extern __typeof (strptime_l) __strptime_l;

libc_hidden_proto (time)
libc_hidden_proto (asctime)
libc_hidden_proto (mktime)
libc_hidden_proto (timelocal)
libc_hidden_proto (localtime)
libc_hidden_proto (strftime)
libc_hidden_proto (strptime)

extern __typeof (clock_gettime) __clock_gettime;
libc_hidden_proto (__clock_gettime)
extern __typeof (clock_settime) __clock_settime;
libc_hidden_proto (__clock_settime)

/* Now define the internal interfaces.  */
struct tm;

/* Defined in mktime.c.  */
extern const unsigned short int __mon_yday[2][13] attribute_hidden;

/* Defined in localtime.c.  */
extern struct tm _tmbuf attribute_hidden;

/* Defined in tzset.c.  */
extern char *__tzstring (const char *string) attribute_hidden;

extern int __use_tzfile attribute_hidden;

extern void __tzfile_read (const char *file, size_t extra,
			   char **extrap) attribute_hidden;
extern void __tzfile_compute (__time64_t timer, int use_localtime,
			      long int *leap_correct, int *leap_hit,
			      struct tm *tp) attribute_hidden;
extern void __tzfile_default (const char *std, const char *dst,
			      int stdoff, int dstoff)
  attribute_hidden;
extern void __tzset_parse_tz (const char *tz) attribute_hidden;
extern void __tz_compute (__time64_t timer, struct tm *tm, int use_localtime)
  __THROW attribute_hidden;

#if __TIMESIZE == 64
# define __timespec64 timespec
#else
/* The glibc Y2038-proof struct __timespec64 structure for a time value.
   To keep things Posix-ish, we keep the nanoseconds field a 32-bit
   signed long, but since the Linux field is a 64-bit signed int, we
   pad our tv_nsec with a 32-bit unnamed bit-field padding.

   As a general rule the Linux kernel is ignoring upper 32 bits of
   tv_nsec field.  */
struct __timespec64
{
  __time64_t tv_sec;         /* Seconds */
# if BYTE_ORDER == BIG_ENDIAN
  __int32_t :32;             /* Padding */
  __int32_t tv_nsec;         /* Nanoseconds */
# else
  __int32_t tv_nsec;         /* Nanoseconds */
  __int32_t :32;             /* Padding */
# endif
};
#endif

#if __TIMESIZE == 64
# define __ctime64 ctime
#else
extern char *__ctime64 (const __time64_t *__timer) __THROW;
libc_hidden_proto (__ctime64)
#endif

#if __TIMESIZE == 64
# define __ctime64_r ctime_r
#else
extern char *__ctime64_r (const __time64_t *__restrict __timer,
		          char *__restrict __buf) __THROW;
libc_hidden_proto (__ctime64_r)
#endif

#if __TIMESIZE == 64
# define __localtime64 localtime
#else
extern struct tm *__localtime64 (const __time64_t *__timer);
libc_hidden_proto (__localtime64)
#endif

extern struct tm *__localtime_r (const time_t *__timer,
				 struct tm *__tp) attribute_hidden;
#if __TIMESIZE != 64
extern struct tm *__localtime64_r (const __time64_t *__timer,
				   struct tm *__tp);
libc_hidden_proto (__localtime64_r)

extern __time64_t __mktime64 (struct tm *__tp) __THROW;
libc_hidden_proto (__mktime64)
#endif

extern struct tm *__gmtime_r (const time_t *__restrict __timer,
			      struct tm *__restrict __tp);
libc_hidden_proto (__gmtime_r)

#if __TIMESIZE == 64
# define __gmtime64 gmtime
#else
extern struct tm *__gmtime64 (const __time64_t *__timer);
libc_hidden_proto (__gmtime64)

extern struct tm *__gmtime64_r (const __time64_t *__restrict __timer,
				struct tm *__restrict __tp);
libc_hidden_proto (__gmtime64_r)

extern __time64_t __timegm64 (struct tm *__tp) __THROW;
libc_hidden_proto (__timegm64)
#endif

#if __TIMESIZE == 64
# define __clock_settime64 __clock_settime
#else
extern int __clock_settime64 (clockid_t clock_id,
                              const struct __timespec64 *tp);
libc_hidden_proto (__clock_settime64)
#endif

/* Compute the `struct tm' representation of T,
   offset OFFSET seconds east of UTC,
   and store year, yday, mon, mday, wday, hour, min, sec into *TP.
   Return nonzero if successful.  */
extern int __offtime (__time64_t __timer,
		      long int __offset,
		      struct tm *__tp) attribute_hidden;

extern char *__asctime_r (const struct tm *__tp, char *__buf)
  attribute_hidden;
extern void __tzset (void) attribute_hidden;

/* Prototype for the internal function to get information based on TZ.  */
extern struct tm *__tz_convert (__time64_t timer, int use_localtime,
				struct tm *tp) attribute_hidden;

extern int __nanosleep (const struct timespec *__requested_time,
			struct timespec *__remaining);
hidden_proto (__nanosleep)
extern int __getdate_r (const char *__string, struct tm *__resbufp)
  attribute_hidden;


/* Determine CLK_TCK value.  */
extern int __getclktck (void) attribute_hidden;


/* strptime support.  */
extern char * __strptime_internal (const char *rp, const char *fmt,
				   struct tm *tm, void *statep,
				   locale_t locparam) attribute_hidden;

#if __TIMESIZE == 64
# define __difftime64 __difftime
#else
extern double __difftime64 (__time64_t time1, __time64_t time0);
libc_hidden_proto (__difftime64)
#endif

extern double __difftime (time_t time1, time_t time0);


/* Use in the clock_* functions.  Size of the field representing the
   actual clock ID.  */
#define CLOCK_IDFIELD_SIZE	3

/* Check whether T fits in time_t.  */
static inline bool
in_time_t_range (__time64_t t)
{
  time_t s = t;
  return s == t;
}

/* Convert a known valid struct timeval into a struct __timespec64.  */
static inline struct __timespec64
valid_timeval_to_timespec64 (const struct timeval tv)
{
  struct __timespec64 ts64;

  ts64.tv_sec = tv.tv_sec;
  ts64.tv_nsec = tv.tv_usec * 1000;

  return ts64;
}

/* Convert a known valid struct timespec into a struct __timespec64.  */
static inline struct __timespec64
valid_timespec_to_timespec64 (const struct timespec ts)
{
  struct __timespec64 ts64;

  ts64.tv_sec = ts.tv_sec;
  ts64.tv_nsec = ts.tv_nsec;

  return ts64;
}

/* Convert a valid and within range of struct timespec, struct
   __timespec64 into a struct timespec.  */
static inline struct timespec
valid_timespec64_to_timespec (const struct __timespec64 ts64)
{
  struct timespec ts;

  ts.tv_sec = (time_t) ts64.tv_sec;
  ts.tv_nsec = ts64.tv_nsec;

  return ts;
}

/* Convert a valid and within range of struct timeval struct
   __timespec64 into a struct timeval.  */
static inline struct timeval
valid_timespec64_to_timeval (const struct __timespec64 ts64)
{
  struct timeval tv;

  tv.tv_sec = (time_t) ts64.tv_sec;
  tv.tv_usec = ts64.tv_nsec / 1000;

  return tv;
}

/* Check if a value is in the valid nanoseconds range. Return true if
   it is, false otherwise.  */
static inline bool
valid_nanoseconds (__syscall_slong_t ns)
{
  return __glibc_likely (0 <= ns && ns < 1000000000);
}
#endif
#endif
