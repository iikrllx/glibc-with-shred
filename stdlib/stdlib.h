/* Copyright (C) 1991,92,93,94,95,96,97,98,99 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/*
 *	ISO C Standard: 4.10 GENERAL UTILITIES	<stdlib.h>
 */

#ifndef	_STDLIB_H

#include <features.h>

/* Get size_t, wchar_t and NULL from <stddef.h>.  */
#define		__need_size_t
#ifndef __need_malloc_and_calloc
# define	__need_wchar_t
# define	__need_NULL
#endif
#include <stddef.h>

__BEGIN_DECLS

#ifndef __need_malloc_and_calloc
#define	_STDLIB_H	1

/* Returned by `div'.  */
typedef struct
  {
    int quot;			/* Quotient.  */
    int rem;			/* Remainder.  */
  } div_t;

/* Returned by `ldiv'.  */
#ifndef __ldiv_t_defined
typedef struct
  {
    long int quot;		/* Quotient.  */
    long int rem;		/* Remainder.  */
  } ldiv_t;
# define __ldiv_t_defined	1
#endif

#if defined __USE_ISOC99 && !defined __lldiv_t_defined
/* Returned by `lldiv'.  */
__extension__ typedef struct
  {
    long long int quot;		/* Quotient.  */
    long long int rem;		/* Remainder.  */
  } lldiv_t;
# define __lldiv_t_defined	1
#endif


/* The largest number rand will return (same as INT_MAX).  */
#define	RAND_MAX	2147483647


/* We define these the same for all machines.
   Changes from this to the outside world should be done in `_exit'.  */
#define	EXIT_FAILURE	1	/* Failing exit status.  */
#define	EXIT_SUCCESS	0	/* Successful exit status.  */


/* Maximum length of a multibyte character in the current locale.  */
#define	MB_CUR_MAX	(__ctype_get_mb_cur_max ())
extern size_t __ctype_get_mb_cur_max (void) __THROW;


/* Convert a string to a floating-point number.  */
extern double atof (__const char *__nptr) __THROW;
/* Convert a string to an integer.  */
extern int atoi (__const char *__nptr) __THROW;
/* Convert a string to a long integer.  */
extern long int atol (__const char *__nptr) __THROW;

#if defined __USE_ISOC99 || (defined __GNUC__ && defined __USE_MISC)
/* These functions will part of the standard C library in ISO C99.  */
__extension__ extern long long int atoll (__const char *__nptr) __THROW;
#endif

/* Convert a string to a floating-point number.  */
extern double strtod (__const char *__restrict __nptr,
		      char **__restrict __endptr) __THROW;

#ifdef	__USE_ISOC99
/* Likewise for `float' and `long double' sizes of floating-point numbers.  */
extern float strtof (__const char *__restrict __nptr,
		     char **__restrict __endptr) __THROW;

extern long double strtold (__const char *__restrict __nptr,
			    char **__restrict __endptr) __THROW;
#endif

/* Convert a string to a long integer.  */
extern long int strtol (__const char *__restrict __nptr,
			char **__restrict __endptr, int __base) __THROW;
/* Convert a string to an unsigned long integer.  */
extern unsigned long int strtoul (__const char *__restrict __nptr,
				  char **__restrict __endptr, int __base)
     __THROW;

#if defined __GNUC__ && defined __USE_BSD
/* Convert a string to a quadword integer.  */
__extension__
extern long long int strtoq (__const char *__restrict __nptr,
			     char **__restrict __endptr, int __base) __THROW;
/* Convert a string to an unsigned quadword integer.  */
__extension__
extern unsigned long long int strtouq (__const char *__restrict __nptr,
				       char **__restrict __endptr, int __base)
     __THROW;
#endif /* GCC and use BSD.  */

#if defined __USE_ISOC99 || (defined __GNUC__ && defined __USE_MISC)
/* These functions will part of the standard C library in ISO C99.  */

/* Convert a string to a quadword integer.  */
__extension__
extern long long int strtoll (__const char *__restrict __nptr,
			      char **__restrict __endptr, int __base) __THROW;
/* Convert a string to an unsigned quadword integer.  */
__extension__
extern unsigned long long int strtoull (__const char *__restrict __nptr,
					char **__restrict __endptr, int __base)
     __THROW;
#endif /* ISO C99 or GCC and use MISC.  */


#ifdef __USE_GNU
/* The concept of one static locale per category is not very well
   thought out.  Many applications will need to process its data using
   information from several different locales.  Another application is
   the implementation of the internationalization handling in the
   upcoming ISO C++ standard library.  To support this another set of
   the functions using locale data exist which have an additional
   argument.

   Attention: all these functions are *not* standardized in any form.
   This is a proof-of-concept implementation.  */

/* Structure for reentrant locale using functions.  This is an
   (almost) opaque type for the user level programs.  */
# include <xlocale.h>

/* Special versions of the functions above which take the locale to
   use as an additional parameter.  */
extern long int __strtol_l (__const char *__restrict __nptr,
			    char **__restrict __endptr, int __base,
			    __locale_t __loc) __THROW;

extern unsigned long int __strtoul_l (__const char *__restrict __nptr,
				      char **__restrict __endptr,
				      int __base, __locale_t __loc) __THROW;

__extension__
extern long long int __strtoll_l (__const char *__restrict __nptr,
				  char **__restrict __endptr, int __base,
				  __locale_t __loc) __THROW;

__extension__
extern unsigned long long int __strtoull_l (__const char *__restrict __nptr,
					    char **__restrict __endptr,
					    int __base, __locale_t __loc)
     __THROW;

extern double __strtod_l (__const char *__restrict __nptr,
			  char **__restrict __endptr, __locale_t __loc)
     __THROW;

extern float __strtof_l (__const char *__restrict __nptr,
			 char **__restrict __endptr, __locale_t __loc) __THROW;

extern long double __strtold_l (__const char *__restrict __nptr,
				char **__restrict __endptr,
				__locale_t __loc) __THROW;
#endif /* GNU */


/* The internal entry points for `strtoX' take an extra flag argument
   saying whether or not to parse locale-dependent number grouping.  */

extern double __strtod_internal (__const char *__restrict __nptr,
				 char **__restrict __endptr, int __group)
     __THROW;
extern float __strtof_internal (__const char *__restrict __nptr,
				char **__restrict __endptr, int __group)
     __THROW;
extern long double __strtold_internal (__const char *__restrict __nptr,
				       char **__restrict __endptr,
				       int __group) __THROW;
#ifndef __strtol_internal_defined
extern long int __strtol_internal (__const char *__restrict __nptr,
				   char **__restrict __endptr,
				   int __base, int __group) __THROW;
# define __strtol_internal_defined	1
#endif
#ifndef __strtoul_internal_defined
extern unsigned long int __strtoul_internal (__const char *__restrict __nptr,
					     char **__restrict __endptr,
					     int __base, int __group) __THROW;
# define __strtoul_internal_defined	1
#endif
#if defined __GNUC__ || defined __USE_ISOC99
# ifndef __strtoll_internal_defined
__extension__
extern long long int __strtoll_internal (__const char *__restrict __nptr,
					 char **__restrict __endptr,
					 int __base, int __group) __THROW;
#  define __strtoll_internal_defined	1
# endif
# ifndef __strtoull_internal_defined
__extension__
extern unsigned long long int __strtoull_internal (__const char *
						   __restrict __nptr,
						   char **__restrict __endptr,
						   int __base, int __group)
     __THROW;
#  define __strtoull_internal_defined	1
# endif
#endif /* GCC */

#if defined __OPTIMIZE__ && !defined __OPTIMIZE_SIZE__ \
    && defined __USE_EXTERN_INLINES
/* Define inline functions which call the internal entry points.  */

extern __inline double
strtod (__const char *__restrict __nptr, char **__restrict __endptr) __THROW
{
  return __strtod_internal (__nptr, __endptr, 0);
}
extern __inline long int
strtol (__const char *__restrict __nptr, char **__restrict __endptr,
	int __base) __THROW
{
  return __strtol_internal (__nptr, __endptr, __base, 0);
}
extern __inline unsigned long int
strtoul (__const char *__restrict __nptr, char **__restrict __endptr,
	 int __base) __THROW
{
  return __strtoul_internal (__nptr, __endptr, __base, 0);
}

# ifdef __USE_ISOC99
extern __inline float
strtof (__const char *__restrict __nptr, char **__restrict __endptr) __THROW
{
  return __strtof_internal (__nptr, __endptr, 0);
}
extern __inline long double
strtold (__const char *__restrict __nptr, char **__restrict __endptr) __THROW
{
  return __strtold_internal (__nptr, __endptr, 0);
}
# endif

# ifdef __USE_BSD
__extension__ extern __inline long long int
strtoq (__const char *__restrict __nptr, char **__restrict __endptr,
	int __base) __THROW
{
  return __strtoll_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline unsigned long long int
strtouq (__const char *__restrict __nptr, char **__restrict __endptr,
	 int __base) __THROW
{
  return __strtoull_internal (__nptr, __endptr, __base, 0);
}
# endif

# if defined __USE_MISC || defined __USE_ISOC99
__extension__ extern __inline long long int
strtoll (__const char *__restrict __nptr, char **__restrict __endptr,
	 int __base) __THROW
{
  return __strtoll_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline unsigned long long int
strtoull (__const char * __restrict __nptr, char **__restrict __endptr,
	  int __base) __THROW
{
  return __strtoull_internal (__nptr, __endptr, __base, 0);
}
# endif

extern __inline double
atof (__const char *__nptr) __THROW
{
  return strtod (__nptr, (char **) NULL);
}
extern __inline int
atoi (__const char *__nptr) __THROW
{
  return (int) strtol (__nptr, (char **) NULL, 10);
}
extern __inline long int
atol (__const char *__nptr) __THROW
{
  return strtol (__nptr, (char **) NULL, 10);
}

# if defined __USE_MISC || defined __USE_ISOC99
__extension__ extern __inline long long int
atoll (__const char *__nptr) __THROW
{
  return strtoll (__nptr, (char **) NULL, 10);
}
# endif
#endif /* Optimizing and Inlining.  */


#if defined __USE_SVID || defined __USE_XOPEN_EXTENDED
/* Convert N to base 64 using the digits "./0-9A-Za-z", least-significant
   digit first.  Returns a pointer to static storage overwritten by the
   next call.  */
extern char *l64a (long int __n) __THROW;

/* Read a number from a string S in base 64 as above.  */
extern long int a64l (__const char *__s) __THROW;


# include <sys/types.h>	/* we need int32_t... */

/* These are the functions that actually do things.  The `random', `srandom',
   `initstate' and `setstate' functions are those from BSD Unices.
   The `rand' and `srand' functions are required by the ANSI standard.
   We provide both interfaces to the same random number generator.  */
/* Return a random long integer between 0 and RAND_MAX inclusive.  */
extern int32_t random (void) __THROW;

/* Seed the random number generator with the given number.  */
extern void srandom (unsigned int __seed) __THROW;

/* Initialize the random number generator to use state buffer STATEBUF,
   of length STATELEN, and seed it with SEED.  Optimal lengths are 8, 16,
   32, 64, 128 and 256, the bigger the better; values less than 8 will
   cause an error and values greater than 256 will be rounded down.  */
extern void *initstate (unsigned int __seed, void *__statebuf,
			size_t __statelen) __THROW;

/* Switch the random number generator to state buffer STATEBUF,
   which should have been previously initialized by `initstate'.  */
extern void *setstate (void *__statebuf) __THROW;


# ifdef __USE_MISC
/* Reentrant versions of the `random' family of functions.
   These functions all use the following data structure to contain
   state, rather than global state variables.  */

struct random_data
  {
    int32_t *fptr;		/* Front pointer.  */
    int32_t *rptr;		/* Rear pointer.  */
    int32_t *state;		/* Array of state values.  */
    int rand_type;		/* Type of random number generator.  */
    int rand_deg;		/* Degree of random number generator.  */
    int rand_sep;		/* Distance between front and rear.  */
    int32_t *end_ptr;		/* Pointer behind state table.  */
  };

extern int random_r (struct random_data *__restrict __buf,
		     int32_t *__restrict __result) __THROW;

extern int srandom_r (unsigned int __seed, struct random_data *__buf) __THROW;

extern int initstate_r (unsigned int __seed, void *__restrict __statebuf,
			size_t __statelen,
			struct random_data *__restrict __buf) __THROW;

extern int setstate_r (void *__restrict __statebuf,
		       struct random_data *__restrict __buf) __THROW;
# endif	/* Use misc.  */
#endif	/* Use SVID || extended X/Open.  */


/* Return a random integer between 0 and RAND_MAX inclusive.  */
extern int rand (void) __THROW;
/* Seed the random number generator with the given number.  */
extern void srand (unsigned int __seed) __THROW;

#ifdef __USE_POSIX
/* Reentrant interface according to POSIX.1.  */
extern int rand_r (unsigned int *__seed) __THROW;
#endif


#if defined __USE_SVID || defined __USE_XOPEN
/* System V style 48-bit random number generator functions.  */

/* Return non-negative, double-precision floating-point value in [0.0,1.0).  */
extern double drand48 (void) __THROW;
extern double erand48 (unsigned short int __xsubi[3]) __THROW;

/* Return non-negative, long integer in [0,2^31).  */
extern long int lrand48 (void) __THROW;
extern long int nrand48 (unsigned short int __xsubi[3]) __THROW;

/* Return signed, long integers in [-2^31,2^31).  */
extern long int mrand48 (void) __THROW;
extern long int jrand48 (unsigned short int __xsubi[3]) __THROW;

/* Seed random number generator.  */
extern void srand48 (long int __seedval) __THROW;
extern unsigned short int *seed48 (unsigned short int __seed16v[3]) __THROW;
extern void lcong48 (unsigned short int __param[7]) __THROW;

/* Data structure for communication with thread safe versions.  */
struct drand48_data
  {
    unsigned short int x[3];	/* Current state.  */
    unsigned short int a[3];	/* Factor in congruential formula.  */
    unsigned short int c;	/* Additive const. in congruential formula.  */
    unsigned short int old_x[3]; /* Old state.  */
    int init;			/* Flag for initializing.  */
  };

# ifdef __USE_MISC
/* Return non-negative, double-precision floating-point value in [0.0,1.0).  */
extern int drand48_r (struct drand48_data *__restrict __buffer,
		      double *__restrict __result) __THROW;
extern int erand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      double *__restrict __result) __THROW;

/* Return non-negative, long integer in [0,2^31).  */
extern int lrand48_r (struct drand48_data *__restrict __buffer,
		      long int *__restrict __result) __THROW;
extern int nrand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      long int *__restrict __result) __THROW;

/* Return signed, long integers in [-2^31,2^31).  */
extern int mrand48_r (struct drand48_data *__restrict __buffer,
		      long int *__restrict __result) __THROW;
extern int jrand48_r (unsigned short int __xsubi[3],
		      struct drand48_data *__restrict __buffer,
		      long int *__restrict __result) __THROW;

/* Seed random number generator.  */
extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
     __THROW;

extern int seed48_r (unsigned short int __seed16v[3],
		     struct drand48_data *__buffer) __THROW;

extern int lcong48_r (unsigned short int __param[7],
		      struct drand48_data *__buffer) __THROW;
# endif	/* Use misc.  */
#endif	/* Use SVID or X/Open.  */

#endif /* don't just need malloc and calloc */

#ifndef __malloc_and_calloc_defined
#define __malloc_and_calloc_defined
/* Allocate SIZE bytes of memory.  */
extern void *malloc (size_t __size) __THROW __attribute_malloc__;
/* Allocate NMEMB elements of SIZE bytes each, all initialized to 0.  */
extern void *calloc (size_t __nmemb, size_t __size)
     __THROW __attribute_malloc__;
#endif

#ifndef __need_malloc_and_calloc
/* Re-allocate the previously allocated block
   in PTR, making the new block SIZE bytes long.  */
extern void *realloc (void *__ptr, size_t __size) __THROW __attribute_malloc__;
/* Free a block allocated by `malloc', `realloc' or `calloc'.  */
extern void free (void *__ptr) __THROW;

#ifdef	__USE_MISC
/* Free a block.  An alias for `free'.	(Sun Unices).  */
extern void cfree (void *__ptr) __THROW;
#endif /* Use misc.  */

#if defined __USE_GNU || defined __USE_BSD || defined __USE_MISC
# include <alloca.h>
#endif /* Use GNU, BSD, or misc.  */

#if defined __USE_BSD || defined __USE_XOPEN_EXTENDED
/* Allocate SIZE bytes on a page boundary.  The storage cannot be freed.  */
extern void *valloc (size_t __size) __THROW __attribute_malloc__;
#endif


/* Abort execution and generate a core-dump.  */
extern void abort (void) __THROW __attribute__ ((__noreturn__));


/* Register a function to be called when `exit' is called.  */
extern int atexit (void (*__func) (void)) __THROW;

#ifdef	__USE_MISC
/* Register a function to be called with the status
   given to `exit' and the given argument.  */
extern int __on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     __THROW;
extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     __THROW;
#endif

/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
extern void exit (int __status) __THROW __attribute__ ((__noreturn__));

#ifdef __USE_ISOC99
/* Terminate the program with STATUS without calling any of the
   functions registered with `atexit' or `on_exit'.  */
extern void _Exit (int __status) __THROW __attribute__ ((__noreturn__));
#endif


/* Return the value of envariable NAME, or NULL if it doesn't exist.  */
extern char *getenv (__const char *__name) __THROW;

/* This function is similar to the above but returns NULL if the
   programs is running with SUID or SGID enabled.  */
extern char *__secure_getenv (__const char *__name) __THROW;

#if defined __USE_SVID || defined __USE_XOPEN
/* The SVID says this is in <stdio.h>, but this seems a better place.	*/
/* Put STRING, which is of the form "NAME=VALUE", in the environment.
   If there is no `=', remove NAME from the environment.  */
extern int putenv (char *__string) __THROW;
#endif

#ifdef	__USE_BSD
/* Set NAME to VALUE in the environment.
   If REPLACE is nonzero, overwrite an existing value.  */
extern int setenv (__const char *__name, __const char *__value, int __replace)
     __THROW;

/* Remove the variable NAME from the environment.  */
extern void unsetenv (__const char *__name) __THROW;
#endif

#ifdef	__USE_MISC
/* The `clearenv' was planned to be added to POSIX.1 but probably
   never made it.  Nevertheless the POSIX.9 standard (POSIX bindings
   for Fortran 77) requires this function.  */
extern int clearenv (void) __THROW;
#endif


#if defined __USE_MISC || defined __USE_XOPEN_EXTENDED
/* Generate a unique temporary file name from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   Returns TEMPLATE, or a null pointer if it cannot get a unique file name.  */
extern char *mktemp (char *__template) __THROW;

/* Generate a unique temporary file name from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the filename unique.
   Returns a file descriptor open on the file for reading and writing,
   or -1 if it cannot create a uniquely-named file.  */
extern int mkstemp (char *__template) __THROW;
#endif

#ifdef __USE_BSD
/* Create a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the directory name unique.
   Returns TEMPLATE, or a null pointer if it cannot get a unique name.
   The directory is created mode 700.  */
extern char *mkdtemp (char *__template) __THROW;
#endif


/* Execute the given line as a shell command.  */
extern int system (__const char *__command) __THROW;


#ifdef	__USE_GNU
/* Return a malloc'd string containing the canonical absolute name of the
   named file.  The last file name component need not exist, and may be a
   symlink to a nonexistent file.  */
extern char *canonicalize_file_name (__const char *__name) __THROW;
#endif

#if defined __USE_BSD || defined __USE_XOPEN_EXTENDED
/* Return the canonical absolute name of file NAME.  The last file name
   component need not exist, and may be a symlink to a nonexistent file.
   If RESOLVED is null, the result is malloc'd; otherwise, if the canonical
   name is PATH_MAX chars or more, returns null with `errno' set to
   ENAMETOOLONG; if the name fits in fewer than PATH_MAX chars, returns the
   name in RESOLVED.  */
extern char *realpath (__const char *__restrict __name,
		       char *__restrict __resolved) __THROW;
#endif


/* Shorthand for type of comparison functions.  */
#ifndef __COMPAR_FN_T
# define __COMPAR_FN_T
typedef int (*__compar_fn_t) (__const void *, __const void *);

# ifdef	__USE_GNU
typedef __compar_fn_t comparison_fn_t;
# endif
#endif

/* Do a binary search for KEY in BASE, which consists of NMEMB elements
   of SIZE bytes each, using COMPAR to perform the comparisons.  */
extern void *bsearch (__const void *__key, __const void *__base,
		      size_t __nmemb, size_t __size, __compar_fn_t __compar);

/* Sort NMEMB elements of BASE, of SIZE bytes each,
   using COMPAR to perform the comparisons.  */
extern void qsort (void *__base, size_t __nmemb, size_t __size,
		   __compar_fn_t __compar);


/* Return the absolute value of X.  */
extern int abs (int __x) __THROW __attribute__ ((__const__));
extern long int labs (long int __x) __THROW __attribute__ ((__const__));
#ifdef __USE_ISOC99
__extension__ extern long long int llabs (long long int __x)
     __THROW __attribute__ ((__const__));
#endif


/* Return the `div_t', `ldiv_t' or `lldiv_t' representation
   of the value of NUMER over DENOM. */
/* GCC may have built-ins for these someday.  */
extern div_t div (int __numer, int __denom)
     __THROW __attribute__ ((__const__));
extern ldiv_t ldiv (long int __numer, long int __denom)
     __THROW __attribute__ ((__const__));
#ifdef __USE_ISOC99
__extension__ extern lldiv_t lldiv (long long int __numer,
				    long long int __denom)
     __THROW __attribute__ ((__const__));
#endif


#if defined __USE_SVID || defined __USE_XOPEN_EXTENDED
/* Convert floating point numbers to strings.  The returned values are
   valid only until another call to the same function.  */

/* Convert VALUE to a string with NDIGIT digits and return a pointer to
   this.  Set *DECPT with the position of the decimal character and *SIGN
   with the sign of the number.  */
extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign) __THROW;

/* Convert VALUE to a string rounded to NDIGIT decimal digits.  Set *DECPT
   with the position of the decimal character and *SIGN with the sign of
   the number.  */
extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign) __THROW;

/* If possible convert VALUE to a string with NDIGIT significant digits.
   Otherwise use exponential representation.  The resulting string will
   be written to BUF.  */
extern char *gcvt (double __value, int __ndigit, char *__buf) __THROW;

/* Long double versions of above functions.  */
extern char *qecvt (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign) __THROW;
extern char *qfcvt (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign) __THROW;
extern char *qgcvt (long double __value, int __ndigit, char *__buf) __THROW;


# ifdef __USE_MISC
/* Reentrant version of the functions above which provide their own
   buffers.  */
extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign, char *__restrict __buf,
		   size_t __len) __THROW;
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
		   int *__restrict __sign, char *__restrict __buf,
		   size_t __len) __THROW;

extern int qecvt_r (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign,
		    char *__restrict __buf, size_t __len) __THROW;
extern int qfcvt_r (long double __value, int __ndigit,
		    int *__restrict __decpt, int *__restrict __sign,
		    char *__restrict __buf, size_t __len) __THROW;
# endif	/* misc */
#endif	/* use MISC || use X/Open Unix */


/* Return the length of the multibyte character
   in S, which is no longer than N.  */
extern int mblen (__const char *__s, size_t __n) __THROW;
/* Return the length of the given multibyte character,
   putting its `wchar_t' representation in *PWC.  */
extern int mbtowc (wchar_t *__restrict __pwc,
		   __const char *__restrict __s, size_t __n) __THROW;
/* Put the multibyte character represented
   by WCHAR in S, returning its length.  */
extern int wctomb (char *__s, wchar_t __wchar) __THROW;


/* Convert a multibyte string to a wide char string.  */
extern size_t mbstowcs (wchar_t *__restrict  __pwcs,
			__const char *__restrict __s, size_t __n) __THROW;
/* Convert a wide char string to multibyte string.  */
extern size_t wcstombs (char *__restrict __s,
			__const wchar_t *__restrict __pwcs, size_t __n)
     __THROW;


#ifdef __USE_SVID
/* Determine whether the string value of RESPONSE matches the affirmation
   or negative response expression as specified by the LC_MESSAGES category
   in the program's current locale.  Returns 1 if affirmative, 0 if
   negative, and -1 if not matching.  */
extern int rpmatch (__const char *__response) __THROW;
#endif


#ifdef __USE_XOPEN_EXTENDED
/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
extern int getsubopt (char **__restrict __optionp,
		      char *__const *__restrict __tokens,
		      char **__restrict __valuep) __THROW;
#endif


#ifdef __USE_XOPEN

/* Setup DES tables according KEY.  */
extern void setkey (__const char *__key) __THROW;

/* X/Open pseudo terminal handling.  */

/* The next four functions all take a master pseudo-tty fd and
   perform an operation on the associated slave:  */

/* Chown the slave to the calling user.  */
extern int grantpt (int __fd) __THROW;

/* Release an internal lock so the slave can be opened.
   Call after grantpt().  */
extern int unlockpt (int __fd) __THROW;

/* Return the pathname of the pseudo terminal slave assoicated with
   the master FD is open on, or NULL on errors.
   The returned storage is good until the next call to this function.  */
extern char *ptsname (int __fd) __THROW;
#endif

#ifdef __USE_GNU
/* Store at most BUFLEN characters of the pathname of the slave pseudo
   terminal associated with the master FD is open on in BUF.
   Return 0 on success, otherwise an error number.  */
extern int ptsname_r (int __fd, char *__buf, size_t __buflen) __THROW;

/* Open a master pseudo terminal and return its file descriptor.  */
extern int getpt (void) __THROW;
#endif

#ifdef __USE_BSD
/* Put the 1 minute, 5 minute and 15 minute load averages into the first
   NELEM elements of LOADAVG.  Return the number written (never more than
   three, but may be less than NELEM), or -1 if an error occurred.  */
extern int getloadavg (double __loadavg[], int __nelem) __THROW;
#endif

#endif /* don't just need malloc and calloc */
#undef __need_malloc_and_calloc

__END_DECLS

#endif /* stdlib.h  */
