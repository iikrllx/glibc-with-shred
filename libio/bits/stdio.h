/* Optimizing macros and inline functions for stdio functions.
   Copyright (C) 198 Free Software Foundation, Inc.

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

#ifndef _STDIO_H
# error "Never include <bits/stdio.h> directly; use <stdio.h> instead."
#endif

#ifdef __cplusplus
# define __STDIO_INLINE inline
#else
# define __STDIO_INLINE extern __inline
#endif


#ifdef __USE_EXTERN_INLINES
/* Write formatted output to stdout from argument list ARG.  */
__STDIO_INLINE int
vprintf (__const char *__restrict __fmt, _G_va_list __arg) __THROW
{
  return vfprintf (stdout, __fmt, __arg);
}

/* Read a character from stdin.  */
__STDIO_INLINE int
getchar (void) __THROW
{
  return _IO_getc (stdin);
}


# if defined __USE_POSIX || defined __USE_MISC
/* This is defined in POSIX.1:1996.  */
__STDIO_INLINE int
getc_unlocked (FILE *__fp) __THROW
{
  return _IO_getc_unlocked (__fp);
}

/* This is defined in POSIX.1:1996.  */
__STDIO_INLINE int
getchar_unlocked (void) __THROW
{
  return _IO_getc_unlocked (stdin);
}
# endif	/* POSIX || misc */


/* Write a character to stdout.  */
__STDIO_INLINE int
putchar (int __c) __THROW
{
  return _IO_putc (__c, stdout);
}


# ifdef __USE_MISC
/* Faster version when locking is not necessary.  */
__STDIO_INLINE int
fputc_unlocked (int __c, FILE *__stream) __THROW
{
  return _IO_putc_unlocked (__c, __stream);
}
# endif /* misc */


# if defined __USE_POSIX || defined __USE_MISC
/* This is defined in POSIX.1:1996.  */
__STDIO_INLINE int
putc_unlocked (int __c, FILE *__stream) __THROW
{
  return _IO_putc_unlocked (__c, __stream);
}

/* This is defined in POSIX.1:1996.  */
__STDIO_INLINE int
putchar_unlocked (int __c) __THROW
{
  return _IO_putc_unlocked (__c, stdout);
}
# endif	/* POSIX || misc */


# ifdef	__USE_GNU
/* Like `getdelim', but reads up to a newline.  */
__STDIO_INLINE _IO_ssize_t
getline (char **__lineptr, size_t *__n, FILE *__stream) __THROW
{
  return __getdelim (__lineptr, __n, '\n', __stream);
}
# endif /* GNU */


# ifdef __USE_MISC
/* Faster versions when locking is not required.  */
__STDIO_INLINE int
feof_unlocked (FILE *__stream) __THROW
{
  return _IO_feof_unlocked (__stream);
}

/* Faster versions when locking is not required.  */
__STDIO_INLINE int
ferror_unlocked (FILE *__stream) __THROW
{
  return _IO_ferror_unlocked (__stream);
}
# endif /* misc */

#endif /* Use extern inlines.  */


#if defined __USE_MISC && defined __GNUC__ && defined __OPTIMIZE__
/* Perform some simple optimizations.  */
# define fread_unlocked(ptr, size, n, stream) \
  (__extension__ ((((__builtin_constant_p (size)			      \
		     && ((size) == 0 || __builtin_constant_p (n)))	      \
		    || (__builtin_constant_p (n) && (n) == 0))		      \
		   && (size_t) ((size) * (n)) <= 8)			      \
		  ? ({ char *__ptr = (char *) (ptr);			      \
		       FILE *__stream = (stream);			      \
		       size_t __size = (size);				      \
		       size_t __n = (n);				      \
		       size_t __readres = __n;				      \
		       size_t __cnt = __size * __n + 1;			      \
		       while (--__cnt > 0)				      \
			 {						      \
			   int __c = _IO_getc_unlocked (__stream);	      \
			   if (__c == EOF)				      \
			     {						      \
			       __readres = (__size * __n - __cnt) / __size;   \
			       break;					      \
			     }						      \
			   *__ptr++ = __c;				      \
			 }						      \
		       __readres; })					      \
		  : fread_unlocked (ptr, size, n, stream)))

# define fwrite_unlocked(ptr, size, n, stream) \
  (__extension__ ((((__builtin_constant_p (size)			      \
		     && ((size) == 0 || __builtin_constant_p (n)))	      \
		    || (__builtin_constant_p (n) && (n) == 0))		      \
		   && (size_t) ((size) * (n)) <= 8)			      \
		  ? ({ const char *__ptr = (const char *) (ptr);	      \
		       FILE *__stream = (stream);			      \
		       size_t __size = (size);				      \
		       size_t __n = (n);				      \
		       size_t __writeres = __n;				      \
		       size_t __cnt = __size * __n + 1;			      \
		       while (--__cnt > 0)				      \
			 if (_IO_putc_unlocked (*__ptr++, __stream) == EOF)   \
			   {						      \
			     __writeres = (__size * __n - __cnt) / __size;    \
			     break;					      \
			   }						      \
		       __writeres; })					      \
		  : fwrite_unlocked (ptr, size, n, stream)))
#endif

/* Define helper macro.  */
#undef __STDIO_INLINE
