/* Define ISO C stdio on top of C++ iostreams.
   Copyright (C) 1991, 94, 95, 96, 97, 98 Free Software Foundation, Inc.

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
 *	ISO C Standard: 4.9 INPUT/OUTPUT	<stdio.h>
 */

#ifndef _STDIO_H

#ifndef __need_FILE
# define _STDIO_H	1
# include <features.h>

__BEGIN_DECLS

# define __need_size_t
# define __need_NULL
# include <stddef.h>

# ifndef __USE_XOPEN
#  define __need___va_list
# endif
# include <stdarg.h>

# include <bits/types.h>
#endif /* Don't need FILE.  */
#undef	__need_FILE


#ifndef	__FILE_defined

/* The opaque type of streams.  */
typedef struct _IO_FILE FILE;

# define __FILE_defined	1
#endif /* FILE not defined.  */


#ifdef	_STDIO_H
#define _STDIO_USES_IOSTREAM

#include <libio.h>

#ifdef __cplusplus
# define __STDIO_INLINE inline
#else
# define __STDIO_INLINE extern __inline
#endif

/* The type of the second argument to `fgetpos' and `fsetpos'.  */
#ifndef __USE_FILE_OFFSET64
typedef _G_fpos_t fpos_t;
#else
typedef _G_fpos64_t fpos_t;
#endif
#ifdef __USE_LARGEFILE64
typedef _G_fpos64_t fpos64_t;
#endif

/* The possibilities for the third argument to `setvbuf'.  */
#define _IOFBF 0 		/* Fully buffered.  */
#define _IOLBF 1		/* Line buffered.  */
#define _IONBF 2		/* No buffering.  */


/* Default buffer size.  */
#ifndef BUFSIZ
# define BUFSIZ _IO_BUFSIZ
#endif


/* End of file character.
   Some things throughout the library rely on this being -1.  */
#ifndef EOF
# define EOF (-1)
#endif


/* The possibilities for the third argument to `fseek'.
   These values should not be changed.  */
#define SEEK_SET	0	/* Seek from beginning of file.  */
#define SEEK_CUR	1	/* Seek from current position.  */
#define SEEK_END	2	/* Seek from end of file.  */


#if defined __USE_SVID || defined __USE_XOPEN
/* Default path prefix for `tempnam' and `tmpnam'.  */
# define P_tmpdir	"/tmp"
#endif


/* Get the values:
   L_tmpnam	How long an array of chars must be to be passed to `tmpnam'.
   TMP_MAX	The minimum number of unique filenames generated by tmpnam
   		(and tempnam when it uses tmpnam's name space),
		or tempnam (the two are separate).
   L_ctermid	How long an array to pass to `ctermid'.
   L_cuserid	How long an array to pass to `cuserid'.
   FOPEN_MAX	Minimum number of files that can be open at once.
   FILENAME_MAX	Maximum length of a filename.  */
#include <bits/stdio_lim.h>


/* Standard streams.  */
extern FILE *stdin;		/* Standard input stream.  */
extern FILE *stdout;		/* Standard output stream.  */
extern FILE *stderr;		/* Standard error output stream.  */


/* Remove file FILENAME.  */
extern int remove __P ((__const char *__filename));
/* Rename file OLD to NEW.  */
extern int rename __P ((__const char *__old, __const char *__new));


/* Create a temporary file and open it read/write.  */
#ifndef __USE_FILE_OFFSET64
extern FILE *tmpfile __P ((void));
#else
# ifdef __REDIRECT
extern FILE *__REDIRECT (tmpfile, __P ((void)), tmpfile64);
# else
#  define tmpfile tmpfile64
# endif
#endif
#ifdef __USE_LARGEFILE64
extern FILE *tmpfile64 __P ((void));
#endif
/* Generate a temporary filename.  */
extern char *tmpnam __P ((char *__s));

#ifdef __USE_MISC
/* This is the reentrant variant of `tmpnam'.  The only difference is
   that it does not allow S to be NULL.  */
extern char *tmpnam_r __P ((char *__s));
#endif


#if defined __USE_SVID || defined __USE_XOPEN
/* Generate a unique temporary filename using up to five characters of PFX
   if it is not NULL.  The directory to put this file in is searched for
   as follows: First the environment variable "TMPDIR" is checked.
   If it contains the name of a writable directory, that directory is used.
   If not and if DIR is not NULL, that value is checked.  If that fails,
   P_tmpdir is tried and finally "/tmp".  The storage for the filename
   is allocated by `malloc'.  */
extern char *tempnam __P ((__const char *__dir, __const char *__pfx));
#endif


/* Close STREAM.  */
extern int fclose __P ((FILE *__stream));
/* Flush STREAM, or all streams if STREAM is NULL.  */
extern int fflush __P ((FILE *__stream));

#ifdef __USE_MISC
/* Faster versions when locking is not required.  */
extern int fflush_unlocked __P ((FILE *__stream));
#endif

#ifdef __USE_GNU
/* Close all streams.  */
extern int fcloseall __P ((void));
#endif


#ifndef __USE_FILE_OFFSET64
/* Open a file and create a new stream for it.  */
extern FILE *fopen __P ((__const char *__restrict __filename,
			 __const char *__restrict __modes));
/* Open a file, replacing an existing stream with it. */
extern FILE *freopen __P ((__const char *__restrict __filename,
			   __const char *__restrict __modes,
			   FILE *__restrict __stream));
#else
# ifdef __REDIRECT
extern FILE *__REDIRECT (fopen, __P ((__const char *__restrict __filename,
				   __const char *__restrict __modes)),
			 fopen64);
extern FILE *__REDIRECT (freopen, __P ((__const char *__restrict __filename,
					__const char *__restrict __modes,
					FILE *__restrict __stream)),
			 freopen64);
# else
#  define fopen fopen64
#  define freopen freopen64
# endif
#endif
#ifdef __USE_LARGEFILE64
extern FILE *fopen64 __P ((__const char *__restrict __filename,
			   __const char *__restrict __modes));
extern FILE *freopen64 __P ((__const char *__restrict __filename,
			     __const char *__restrict __modes,
			     FILE *__restrict __stream));
#endif

#ifdef	__USE_POSIX
/* Create a new stream that refers to an existing system file descriptor.  */
extern FILE *fdopen __P ((int __fd, __const char *__modes));
#endif

#ifdef	__USE_GNU
/* Create a new stream that refers to the given magic cookie,
   and uses the given functions for input and output.  */
extern FILE *fopencookie __P ((void *__magic_cookie, __const char *__modes,
			       _IO_cookie_io_functions_t __io_funcs));

/* Open a stream that writes into a malloc'd buffer that is expanded as
   necessary.  *BUFLOC and *SIZELOC are updated with the buffer's location
   and the number of characters written on fflush or fclose.  */
extern FILE *open_memstream __P ((char **__bufloc, size_t *__sizeloc));
#endif


/* If BUF is NULL, make STREAM unbuffered.
   Else make it use buffer BUF, of size BUFSIZ.  */
extern void setbuf __P ((FILE *__restrict __stream, char *__restrict __buf));
/* Make STREAM use buffering mode MODE.
   If BUF is not NULL, use N bytes of it for buffering;
   else allocate an internal buffer N bytes long.  */
extern int setvbuf __P ((FILE *__restrict __stream, char *__restrict __buf,
			 int __modes, size_t __n));

#ifdef	__USE_BSD
/* If BUF is NULL, make STREAM unbuffered.
   Else make it use SIZE bytes of BUF for buffering.  */
extern void setbuffer __P ((FILE *__stream, char *__buf, size_t __size));

/* Make STREAM line-buffered.  */
extern void setlinebuf __P ((FILE *__stream));
#endif


/* Write formatted output to STREAM.  */
extern int fprintf __P ((FILE *__restrict __stream,
			 __const char *__restrict __format, ...));
/* Write formatted output to stdout.  */
extern int printf __P ((__const char *__restrict __format, ...));
/* Write formatted output to S.  */
extern int sprintf __P ((char *__restrict __s,
			 __const char *__restrict __format, ...));

/* Write formatted output to S from argument list ARG.  */
extern int vfprintf __P ((FILE *__restrict __s,
			  __const char *__restrict __format,
			  _G_va_list __arg));
/* Write formatted output to stdout from argument list ARG.  */
extern int vprintf __P ((__const char *__restrict __format,
			 _G_va_list __arg));
/* Write formatted output to S from argument list ARG.  */
extern int vsprintf __P ((char *__restrict __s,
			  __const char *__restrict __format,
			  _G_va_list __arg));

#ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
vprintf (__const char *__restrict __fmt, _G_va_list __arg) __THROW
{
  return vfprintf (stdout, __fmt, __arg);
}
#endif /* Use extern inlines.  */

#if defined __USE_BSD || defined __USE_ISOC9X || defined __USE_UNIX98
/* Maximum chars of output to write in MAXLEN.  */
extern int snprintf __P ((char *__restrict __s, size_t __maxlen,
			  __const char *__restrict __format, ...))
     __attribute__ ((__format__ (__printf__, 3, 4)));

extern int __vsnprintf __P ((char *__restrict __s, size_t __maxlen,
			     __const char *__restrict __format,
			     _G_va_list __arg))
     __attribute__ ((__format__ (__printf__, 3, 0)));
extern int vsnprintf __P ((char *__restrict __s, size_t __maxlen,
			   __const char *__restrict __format,
			   _G_va_list __arg))
     __attribute__ ((__format__ (__printf__, 3, 0)));
#endif

#ifdef __USE_GNU
/* Write formatted output to a string dynamically allocated with `malloc'.
   Store the address of the string in *PTR.  */
extern int vasprintf __P ((char **__restrict __ptr,
			   __const char *__restrict __f, _G_va_list __arg))
     __attribute__ ((__format__ (__printf__, 2, 0)));
extern int __asprintf __P ((char **__restrict __ptr,
			    __const char *__restrict __fmt, ...))
     __attribute__ ((__format__ (__printf__, 2, 3)));
extern int asprintf __P ((char **__restrict __ptr,
			  __const char *__restrict __fmt, ...))
     __attribute__ ((__format__ (__printf__, 2, 3)));

/* Write formatted output to a file descriptor.  */
extern int vdprintf __P ((int __fd, __const char *__restrict __fmt,
			  _G_va_list __arg))
     __attribute__ ((__format__ (__printf__, 2, 0)));
extern int dprintf __P ((int __fd, __const char *__restrict __fmt, ...))
     __attribute__ ((__format__ (__printf__, 2, 3)));
#endif


/* Read formatted input from STREAM.  */
extern int fscanf __P ((FILE *__restrict __stream,
			__const char *__restrict __format, ...));
/* Read formatted input from stdin.  */
extern int scanf __P ((__const char *__restrict __format, ...));
/* Read formatted input from S.  */
extern int sscanf __P ((__const char *__restrict __s,
			__const char *__restrict __format, ...));

#ifdef	__USE_ISOC9X
/* Read formatted input from S into argument list ARG.  */
extern int vfscanf __P ((FILE *__restrict __s,
			 __const char *__restrict __format,
			 _G_va_list __arg))
     __attribute__ ((__format__ (__scanf__, 2, 0)));

/* Read formatted input from stdin into argument list ARG.  */
extern int vscanf __P ((__const char *__restrict __format, _G_va_list __arg))
     __attribute__ ((__format__ (__scanf__, 1, 0)));

/* Read formatted input from S into argument list ARG.  */
extern int vsscanf __P ((__const char *__restrict __s,
			 __const char *__restrict __format,
			 _G_va_list __arg))
     __attribute__ ((__format__ (__scanf__, 2, 0)));
#endif /* Use ISO C9x.  */


/* Read a character from STREAM.  */
extern int fgetc __P ((FILE *__stream));
extern int getc __P ((FILE *__stream));

/* Read a character from stdin.  */
extern int getchar __P ((void));

/* The C standard explicitly says this is a macro, so we always do the
   optimization for it.  */
#define getc(_fp) _IO_getc (_fp)

#ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
getchar (void) __THROW
{
  return _IO_getc (stdin);
}
#endif /* Use extern inlines.  */

#if defined __USE_POSIX || defined __USE_MISC
/* These are defined in POSIX.1:1996.  */
extern int getc_unlocked __P ((FILE *__stream));
extern int getchar_unlocked __P ((void));

# ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
getc_unlocked (FILE *__fp) __THROW
{
  return _IO_getc_unlocked (__fp);
}

__STDIO_INLINE int
getchar_unlocked (void) __THROW
{
  return _IO_getc_unlocked (stdin);
}
# endif /* Use extern inlines.  */
#endif /* Use POSIX or MISC.  */


/* Write a character to STREAM.  */
extern int fputc __P ((int __c, FILE *__stream));
extern int putc __P ((int __c, FILE *__stream));

/* Write a character to stdout.  */
extern int putchar __P ((int __c));

/* The C standard explicitly says this can be a macro,
   so we always do the optimization for it.  */
#define putc(_ch, _fp) _IO_putc (_ch, _fp)

#ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
putchar (int __c) __THROW
{
  return _IO_putc (__c, stdout);
}
#endif	/* Use extern inlines.  */

#ifdef __USE_MISC
/* Faster version when locking is not necessary.  */
extern int fputc_unlocked __P ((int __c, FILE *__stream));

# ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
fputc_unlocked (int __c, FILE *__stream) __THROW
{
  return _IO_putc_unlocked (__c, __stream);
}
# endif /* Use extern inlines.  */
#endif /* Use MISC.  */

#if defined __USE_POSIX || defined __USE_MISC
/* These are defined in POSIX.1:1996.  */
extern int putc_unlocked __P ((int __c, FILE *__stream));
extern int putchar_unlocked __P ((int __c));

# ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
putc_unlocked (int __c, FILE *__stream) __THROW
{
  return _IO_putc_unlocked (__c, __stream);
}

__STDIO_INLINE int
putchar_unlocked (int __c) __THROW
{
  return _IO_putc_unlocked (__c, stdout);
}
# endif /* Use extern inlines.  */
#endif /* Use POSIX or MISC.  */


#if defined __USE_SVID || defined __USE_MISC || defined __USE_XOPEN
/* Get a word (int) from STREAM.  */
extern int getw __P ((FILE *__stream));

/* Write a word (int) to STREAM.  */
extern int putw __P ((int __w, FILE *__stream));
#endif


/* Get a newline-terminated string of finite length from STREAM.  */
extern char *fgets __P ((char *__restrict __s, int __n,
			 FILE *__restrict __stream));

#ifdef __USE_GNU
/* This function does the same as `fgets' but does not lock the stream.  */
extern char *fgets_unlocked __P ((char *__restrict __s, int __n,
				  FILE *__restrict __stream));
#endif

/* Get a newline-terminated string from stdin, removing the newline.
   DO NOT USE THIS FUNCTION!!  There is no limit on how much it will read.  */
extern char *gets __P ((char *__s));


#ifdef	__USE_GNU
/* Read up to (and including) a DELIMITER from STREAM into *LINEPTR
   (and null-terminate it). *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'd as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */
extern _IO_ssize_t __getdelim __P ((char **__lineptr, size_t *__n,
				    int __delimiter, FILE *__stream));
extern _IO_ssize_t getdelim __P ((char **__lineptr, size_t *__n,
				  int __delimiter, FILE *__stream));

/* Like `getdelim', but reads up to a newline.  */
extern _IO_ssize_t getline __P ((char **__lineptr, size_t *__n,
				 FILE *__stream));

# ifdef __USE_EXTERN_INLINES
__STDIO_INLINE _IO_ssize_t
getline (char **__lineptr, size_t *__n, FILE *__stream) __THROW
{
  return __getdelim (__lineptr, __n, '\n', __stream);
}
# endif /* Use extern inlines.  */
#endif


/* Write a string to STREAM.  */
extern int fputs __P ((__const char *__restrict __s,
		       FILE *__restrict __stream));

#ifdef __USE_GNU
/* This function does the same as `fputs' but does not lock the stream.  */
extern int fputs_unlocked __P ((__const char *__restrict __s,
				FILE *__restrict __stream));
#endif

/* Write a string, followed by a newline, to stdout.  */
extern int puts __P ((__const char *__s));


/* Push a character back onto the input buffer of STREAM.  */
extern int ungetc __P ((int __c, FILE *__stream));


/* Read chunks of generic data from STREAM.  */
extern size_t fread __P ((void *__restrict __ptr, size_t __size,
			  size_t __n, FILE *__restrict __stream));
/* Write chunks of generic data to STREAM.  */
extern size_t fwrite __P ((__const void *__restrict __ptr, size_t __size,
			   size_t __n, FILE *__restrict __s));

#ifdef __USE_MISC
/* Faster versions when locking is not necessary.  */
extern size_t fread_unlocked __P ((void *__restrict __ptr, size_t __size,
				   size_t __n, FILE *__restrict __stream));
extern size_t fwrite_unlocked __P ((__const void *__restrict __ptr,
				    size_t __size, size_t __n,
				    FILE *__restrict __stream));
#endif


/* Seek to a certain position on STREAM.  */
extern int fseek __P ((FILE *__stream, long int __off, int __whence));
/* Return the current position of STREAM.  */
extern long int ftell __P ((FILE *__stream));
/* Rewind to the beginning of STREAM.  */
extern void rewind __P ((FILE *__stream));

/* The Single Unix Specification, Version 2, specifies an alternative,
   more adequate interface for the two functions above which deal with
   file offset.  `long int' is not the right type.  These definitions
   are originally defined in the Large File Support API.  */

/* Types needed in these functions.  */
#ifndef off_t
# ifndef __USE_FILE_OFFSET64
typedef __off_t off_t;
# else
typedef __off64_t off_t;
# endif
# define off_t off_t
#endif

#if defined __USE_LARGEFILE64 && !defined off64_t
typedef __off64_t off64_t;
# define off64_t off64_t
#endif


#ifndef __USE_FILE_OFFSET64
# ifdef __USE_UNIX98
/* Seek to a certain position on STREAM.  */
extern int fseeko __P ((FILE *__stream, __off_t __off, int __whence));
/* Return the current position of STREAM.  */
extern __off_t ftello __P ((FILE *__stream));
# endif

/* Get STREAM's position.  */
extern int fgetpos __P ((FILE *__restrict __stream,
			 fpos_t *__restrict __pos));
/* Set STREAM's position.  */
extern int fsetpos __P ((FILE *__stream, __const fpos_t *__pos));
#else
# ifdef __REDIRECT
#  ifdef __USE_UNIX98
extern int __REDIRECT (fseeko,
		       __P ((FILE *__stream, __off64_t __off, int __whence)),
		       fseeko64);
extern __off64_t __REDIRECT (ftello, __P ((FILE *__stream)), ftello64);
#  endif
extern int __REDIRECT (fgetpos, __P ((FILE *__restrict __stream,
				      fpos_t *__restrict __pos)), fgetpos64);
extern int __REDIRECT (fsetpos, __P ((FILE *__stream, __const fpos_t *__pos)),
		       fsetpos64);
# else
#  ifdef __USE_UNIX98
#   define fseeko fseeko64
#   define ftello ftello64
#  endif
#  define fgetpos fgetpos64
#  define fsetpos fsetpos64
# endif
#endif

#ifdef __USE_LARGEFILE64
# ifdef __USE_UNIX98
extern int fseeko64 __P ((FILE *__stream, __off64_t __off, int __whence));
extern __off64_t ftello64 __P ((FILE *__stream));
# endif
extern int fgetpos64 __P ((FILE *__restrict __stream,
			   fpos64_t *__restrict __pos));
extern int fsetpos64 __P ((FILE *__stream, __const fpos64_t *__pos));
#endif

/* Clear the error and EOF indicators for STREAM.  */
extern void clearerr __P ((FILE *__stream));
/* Return the EOF indicator for STREAM.  */
extern int feof __P ((FILE *__stream));
/* Return the error indicator for STREAM.  */
extern int ferror __P ((FILE *__stream));

#ifdef __USE_MISC
/* Faster versions when locking is not required.  */
extern void clearerr_unlocked __P ((FILE *__stream));
extern int feof_unlocked __P ((FILE *__stream));
extern int ferror_unlocked __P ((FILE *__stream));

# ifdef __USE_EXTERN_INLINES
__STDIO_INLINE int
feof_unlocked (FILE *__stream) __THROW
{
  return _IO_feof_unlocked (__stream);
}

__STDIO_INLINE int
ferror_unlocked (FILE *__stream) __THROW
{
  return _IO_ferror_unlocked (__stream);
}
# endif /* Use extern inlines.  */
#endif


/* Print a message describing the meaning of the value of errno.  */
extern void perror __P ((__const char *__s));

/* These variables normally should not be used directly.  The `strerror'
   function provides all the needed functionality.  */
#ifdef	__USE_BSD
extern int sys_nerr;
extern __const char *__const sys_errlist[];
#endif
#ifdef	__USE_GNU
extern int _sys_nerr;
extern __const char *__const _sys_errlist[];
#endif


#ifdef	__USE_POSIX
/* Return the system file descriptor for STREAM.  */
extern int fileno __P ((FILE *__stream));
#endif /* Use POSIX.  */

#ifdef __USE_MISC
/* Faster version when locking is not required.  */
extern int fileno_unlocked __P ((FILE *__stream));
#endif


#if (defined __USE_POSIX2 || defined __USE_SVID  || defined __USE_BSD || \
     defined __USE_MISC)
/* Create a new stream connected to a pipe running the given command.  */
extern FILE *popen __P ((__const char *__command, __const char *__modes));

/* Close a stream opened by popen and return the status of its child.  */
extern int pclose __P ((FILE *__stream));
#endif


#ifdef	__USE_POSIX
/* Return the name of the controlling terminal.  */
extern char *ctermid __P ((char *__s));
#endif /* Use POSIX.  */


#ifdef __USE_XOPEN
/* Return the name of the current user.  */
extern char *cuserid __P ((char *__s));
#endif /* Use X/Open.  */


#ifdef	__USE_GNU
struct obstack;			/* See <obstack.h>.  */

/* Write formatted output to an obstack.  */
extern int obstack_printf __P ((struct obstack *__obstack,
				__const char *__format, ...));
extern int obstack_vprintf __P ((struct obstack *__obstack,
				 __const char *__format,
				 _G_va_list __args));
#endif /* Use GNU.  */


#if defined __USE_POSIX || defined __USE_MISC
/* These are defined in POSIX.1:1996.  */

/* Acquire ownership of STREAM.  */
extern void flockfile __P ((FILE *__stream));

/* Try to acquire ownership of STREAM but do not block if it is not
   possible.  */
extern int ftrylockfile __P ((FILE *__stream));

/* Relinquish the ownership granted for STREAM.  */
extern void funlockfile __P ((FILE *__stream));
#endif /* POSIX || misc */

#if defined __USE_XOPEN && !defined __USE_GNU
/* The X/Open standard requires some functions and variables to be
   declared here which do not belong into this header.  But we have to
   follow.  In GNU mode we don't do this nonsense.  */
# define __need_getopt
# include <getopt.h>
#endif

__END_DECLS

/* Define helper macro.  */
#undef __STDIO_INLINE

#endif /* <stdio.h> included.  */

#endif /* !_STDIO_H */
