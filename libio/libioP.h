/*
Copyright (C) 1993 Free Software Foundation

This file is part of the GNU IO Library.  This library is free
software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option)
any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this library; see the file COPYING.  If not, write to the Free
Software Foundation, 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

As a special exception, if you link this library with files
compiled with a GNU compiler to produce an executable, this does not cause
the resulting executable to be covered by the GNU General Public License.
This exception does not however invalidate any other reasons why
the executable file might be covered by the GNU General Public License. */

#include <errno.h>
#ifndef errno
extern int errno;
#endif
#include <libc-lock.h>

#include "iolibio.h"

#if defined (__STDC__) || defined (_AIX) || (defined (__mips) && defined (_SYSTYPE_SVR4)) || defined(__cplusplus)
/* All known AIX compilers implement these things (but don't always
   define __STDC__).  The RISC/OS MIPS compiler defines these things
   in SVR4 mode, but does not define __STDC__.  */

#define	AND		,
#define	DEFUN(name, arglist, args)	name(args)
#define	DEFUN_VOID(name)		name(void)

#else	/* Not ANSI C.  */

#define	AND		;
#ifndef const /* some systems define it in header files for non-ansi mode */
#define	const
#endif
#define	DEFUN(name, arglist, args)	name arglist args;
#define	DEFUN_VOID(name)		name()
#endif	/* ANSI C.  */

#ifdef __cplusplus
extern "C" {
#endif

#define _IO_seek_set 0
#define _IO_seek_cur 1
#define _IO_seek_end 2

typedef int (*_IO_overflow_t) __P((_IO_FILE*, int));
typedef int (*_IO_underflow_t) __P((_IO_FILE*));
typedef _IO_size_t (*_IO_xsputn_t) __P((_IO_FILE*,const void*,_IO_size_t));
typedef _IO_size_t (*_IO_xsgetn_t) __P((_IO_FILE*, void*, _IO_size_t));
typedef _IO_ssize_t (*_IO_read_t) __P((_IO_FILE*, void*, _IO_ssize_t));
typedef _IO_ssize_t (*_IO_write_t) __P((_IO_FILE*,const void*,_IO_ssize_t));
typedef int (*_IO_stat_t) __P((_IO_FILE*, void*));
typedef _IO_fpos_t (*_IO_seek_t) __P((_IO_FILE*, _IO_off_t, int));
typedef int (*_IO_doallocate_t) __P((_IO_FILE*));
typedef int (*_IO_pbackfail_t) __P((_IO_FILE*, int));
typedef _IO_FILE* (*_IO_setbuf_t) __P((_IO_FILE*, char *, _IO_ssize_t));
typedef int (*_IO_sync_t) __P((_IO_FILE*));
typedef void (*_IO_finish_t) __P((_IO_FILE*)); /* finalize */
typedef int (*_IO_close_t) __P((_IO_FILE*)); /* finalize */
typedef _IO_fpos_t (*_IO_seekoff_t) __P((_IO_FILE*, _IO_off_t, int, int));

/* The _IO_seek_cur and _IO_seek_end options are not allowed. */
typedef _IO_fpos_t (*_IO_seekpos_t) __P((_IO_FILE*, _IO_fpos_t, int));

#if  !_IO_UNIFIED_JUMPTABLES
#define _IO_JUMPS(THIS) (THIS)->_jumps
#else
#define _IO_JUMPS(THIS) ((struct _IO_FILE_plus*)(THIS))->vtable
#endif

#if  !_IO_UNIFIED_JUMPTABLES
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
#define JUMP0(FUNC, THIS) _IO_JUMPS(THIS)->FUNC(THIS)
#define JUMP1(FUNC, THIS, X1) _IO_JUMPS(THIS)->FUNC(THIS, X1)
#define JUMP2(FUNC, THIS, X1, X2) _IO_JUMPS(THIS)->FUNC(THIS, X1, X2)
#define JUMP3(FUNC, THIS, X1, X2, X3) _IO_JUMPS(THIS)->FUNC(THIS, X1, X2, X3)
#define JUMP_INIT(NAME, VALUE) VALUE
#else
#define JUMP_FIELD(TYPE, NAME) struct { short delta1, delta2; TYPE pfn; } NAME
#define JUMP0(FUNC, THIS) _IO_JUMPS(THIS)->FUNC.pfn(THIS)
#define JUMP1(FUNC, THIS, X1) _IO_JUMPS(THIS)->FUNC.pfn(THIS, X1)
#define JUMP2(FUNC, THIS, X1, X2) _IO_JUMPS(THIS)->FUNC.pfn(THIS, X1, X2)
#define JUMP3(FUNC, THIS, X1,X2,X3) _IO_JUMPS(THIS)->FUNC.pfn(THIS, X1,X2, X3)
#define JUMP_INIT(NAME, VALUE) {0, 0, VALUE}
#endif
#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0)

#define _IO_FINISH(FP) JUMP0(__finish, FP)
#define _IO_OVERFLOW(FP, CH) JUMP1(__overflow, FP, CH)
#define _IO_UNDERFLOW(FP) JUMP0(__underflow, FP)
#define _IO_UFLOW(FP) JUMP0(__uflow, FP)
#define _IO_PBACKFAIL(FP, CH) JUMP1(__pbackfail, FP, CH)
#define _IO_XSPUTN(FP, DATA, N) JUMP2(__xsputn, FP, DATA, N)
#define _IO_XSGETN(FP, DATA, N) JUMP2(__xsgetn, FP, DATA, N)
#define _IO_SEEKOFF(FP, OFF, DIR, MODE) JUMP3(__seekoff, FP, OFF, DIR, MODE)
#define _IO_SEEKPOS(FP, POS, FLAGS) JUMP2(__seekpos, FP, POS, FLAGS)
#define _IO_SETBUF(FP, BUFFER, LENGTH) JUMP2(__setbuf, FP, BUFFER, LENGTH)
#define _IO_SYNC(FP) JUMP0(__sync, FP)
#define _IO_DOALLOCATE(FP) JUMP0(__doallocate, FP)
#define _IO_SYSREAD(FP, DATA, LEN) JUMP2(__read, FP, DATA, LEN)
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2(__write, FP, DATA, LEN)
#define _IO_SYSSEEK(FP, OFFSET, MODE) JUMP2(__seek, FP, OFFSET, MODE)
#define _IO_SYSCLOSE(FP) JUMP0(__close, FP)
#define _IO_SYSSTAT(FP, BUF) JUMP1(__stat, FP, BUF)

#define _IO_CHAR_TYPE char /* unsigned char ? */
#define _IO_INT_TYPE int

struct _IO_jump_t {
    JUMP_FIELD(_G_size_t, __dummy);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
#if 0
    get_column;
    set_column;
#endif
};

/* We always allocate an extra word following an _IO_FILE.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus {
  _IO_FILE file;
#if _IO_UNIFIED_JUMPTABLES
  const struct _IO_jump_t *vtable;
#else
  const void *vtable;
#endif
};

/* Generic functions */

extern _IO_fpos_t _IO_seekoff __P((_IO_FILE*, _IO_off_t, int, int));
extern _IO_fpos_t _IO_seekpos __P((_IO_FILE*, _IO_fpos_t, int));

extern int _IO_switch_to_get_mode __P((_IO_FILE*));
extern void _IO_init __P((_IO_FILE*, int));
extern int _IO_sputbackc __P((_IO_FILE*, int));
extern int _IO_sungetc __P((_IO_FILE*));
extern void _IO_un_link __P((_IO_FILE*));
extern void _IO_link_in __P((_IO_FILE *));
extern void _IO_doallocbuf __P((_IO_FILE*));
extern void _IO_unsave_markers __P((_IO_FILE*));
extern void _IO_setb __P((_IO_FILE*, char*, char*, int));
extern unsigned _IO_adjust_column __P((unsigned, const char *, int));
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN(__fp, __s, __n)

/* Marker-related function. */

extern void _IO_init_marker __P((struct _IO_marker *, _IO_FILE *));
extern void _IO_remove_marker __P((struct _IO_marker*));
extern int _IO_marker_difference __P((struct _IO_marker *, struct _IO_marker *));
extern int _IO_marker_delta __P((struct _IO_marker *));
extern int _IO_seekmark __P((_IO_FILE *, struct _IO_marker *, int));

/* Default jumptable functions. */

extern int _IO_default_underflow __P((_IO_FILE*));
extern int _IO_default_uflow __P((_IO_FILE*));
extern int _IO_default_doallocate __P((_IO_FILE*));
extern void _IO_default_finish __P((_IO_FILE *));
extern int _IO_default_pbackfail __P((_IO_FILE*, int));
extern _IO_FILE* _IO_default_setbuf __P((_IO_FILE *, char*, _IO_ssize_t));
extern _IO_size_t _IO_default_xsputn __P((_IO_FILE *, const void*, _IO_size_t));
extern _IO_size_t _IO_default_xsgetn __P((_IO_FILE *, void*, _IO_size_t));
extern _IO_fpos_t _IO_default_seekoff __P((_IO_FILE*, _IO_off_t, int, int));
extern _IO_fpos_t _IO_default_seekpos __P((_IO_FILE*, _IO_fpos_t, int));
extern _IO_ssize_t _IO_default_write __P((_IO_FILE*,const void*,_IO_ssize_t));
extern _IO_ssize_t _IO_default_read __P((_IO_FILE*, void*, _IO_ssize_t));
extern int _IO_default_stat __P((_IO_FILE*, void*));
extern _IO_fpos_t _IO_default_seek __P((_IO_FILE*, _IO_off_t, int));
extern int _IO_default_sync __P((_IO_FILE*));
#define _IO_default_close ((_IO_close_t)_IO_default_sync)

extern struct _IO_jump_t _IO_file_jumps;
extern struct _IO_jump_t _IO_streambuf_jumps;
extern struct _IO_jump_t _IO_proc_jumps;
extern struct _IO_jump_t _IO_str_jumps;
extern int _IO_do_write __P((_IO_FILE*, const char*, _IO_size_t));
extern int _IO_flush_all __P((void));
extern void _IO_cleanup __P((void));
extern void _IO_flush_all_linebuffered __P((void));

#define _IO_do_flush(_f) \
  _IO_do_write(_f, (_f)->_IO_write_base, \
	       (_f)->_IO_write_ptr-(_f)->_IO_write_base)
#define _IO_in_put_mode(_fp) ((_fp)->_flags & _IO_CURRENTLY_PUTTING)
#define _IO_mask_flags(fp, f, mask) \
       ((fp)->_flags = ((fp)->_flags & ~(mask)) | ((f) & (mask)))
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
	(fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
#define _IO_setp(__fp, __p, __ep) \
       ((__fp)->_IO_write_base = (__fp)->_IO_write_ptr = __p, (__fp)->_IO_write_end = (__ep))
#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)
#define _IO_in_backup(fp) ((fp)->_flags & _IO_IN_BACKUP)
#define _IO_have_markers(fp) ((fp)->_markers != NULL)
#define _IO_blen(p) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)

/* Jumptable functions for files. */

extern int _IO_file_doallocate __P((_IO_FILE*));
extern _IO_FILE* _IO_file_setbuf __P((_IO_FILE *, char*, _IO_ssize_t));
extern _IO_fpos_t _IO_file_seekoff __P((_IO_FILE*, _IO_off_t, int, int));
extern _IO_size_t _IO_file_xsputn __P((_IO_FILE*,const void*,_IO_size_t));
extern int _IO_file_stat __P((_IO_FILE*, void*));
extern int _IO_file_close __P((_IO_FILE*));
extern int _IO_file_underflow __P((_IO_FILE *));
extern int _IO_file_overflow __P((_IO_FILE *, int));
#define _IO_file_is_open(__fp) ((__fp)->_fileno >= 0)
extern void _IO_file_init __P((_IO_FILE*));
extern _IO_FILE* _IO_file_attach __P((_IO_FILE*, int));
extern _IO_FILE* _IO_file_fopen __P((_IO_FILE*, const char*, const char*));
extern _IO_ssize_t _IO_file_write __P((_IO_FILE*,const void*,_IO_ssize_t));
extern _IO_ssize_t _IO_file_read __P((_IO_FILE*, void*, _IO_ssize_t));
extern int _IO_file_sync __P((_IO_FILE*));
extern int _IO_file_close_it __P((_IO_FILE*));
extern _IO_fpos_t _IO_file_seek __P((_IO_FILE *, _IO_off_t, int));
extern void _IO_file_finish __P((_IO_FILE*));

/* Other file functions. */
extern _IO_FILE* _IO_file_attach __P((_IO_FILE *, int));

/* Jumptable functions for proc_files. */
extern _IO_FILE* _IO_proc_open __P((_IO_FILE*, const char*, const char *));
extern int _IO_proc_close __P((_IO_FILE*));

/* Jumptable functions for strfiles. */
extern int _IO_str_underflow __P((_IO_FILE*));
extern int _IO_str_overflow __P((_IO_FILE *, int));
extern int _IO_str_pbackfail __P((_IO_FILE*, int));
extern _IO_fpos_t _IO_str_seekoff __P((_IO_FILE*,_IO_off_t,int,int));
extern void _IO_str_finish __P ((_IO_FILE*));

/* Other strfile functions */
extern void _IO_str_init_static __P((_IO_FILE *, char*, int, char*));
extern void _IO_str_init_readonly __P((_IO_FILE *, const char*, int));
extern _IO_ssize_t _IO_str_count __P ((_IO_FILE*));

extern int _IO_vasprintf __P ((char **result_ptr, __const char *format,
			       _IO_va_list args));
extern int _IO_vdprintf __P ((int d, __const char *format, _IO_va_list arg));
extern int _IO_vsnprintf __P ((char *string, _IO_size_t maxlen,
			       __const char *format, _IO_va_list args));


extern _IO_size_t _IO_getline __P((_IO_FILE*,char*,_IO_size_t,int,int));
extern _IO_ssize_t _IO_getdelim __P((char**, _IO_size_t*, int, _IO_FILE*));
extern double _IO_strtod __P((const char *, char **));
extern char * _IO_dtoa __P((double __d, int __mode, int __ndigits,
				int *__decpt, int *__sign, char **__rve));
extern int _IO_outfloat __P((double __value, _IO_FILE *__sb, int __type,
				 int __width, int __precision, int __flags,
				 int __sign_mode, int __fill));

extern _IO_FILE *_IO_list_all;
extern void (*_IO_cleanup_registration_needed) __P ((void));

#ifndef EOF
#define EOF (-1)
#endif
#ifndef NULL
#if !defined(__cplusplus) || defined(__GNUC__)
#define NULL ((void*)0)
#else
#define NULL (0)
#endif
#endif

#define FREE_BUF(_B) free(_B)
#define ALLOC_BUF(_S) (char*)malloc(_S)

#ifndef OS_FSTAT
#define OS_FSTAT fstat
#endif
struct stat;
extern _IO_ssize_t _IO_read __P((int, void*, _IO_size_t));
extern _IO_ssize_t _IO_write __P((int, const void*, _IO_size_t));
extern _IO_off_t _IO_lseek __P((int, _IO_off_t, int));
extern int _IO_close __P((int));
extern int _IO_fstat __P((int, struct stat *));
extern int _IO_vscanf __P((const char *, _IO_va_list));

/* Operations on _IO_fpos_t.
   Normally, these are trivial, but we provide hooks for configurations
   where an _IO_fpos_t is a struct.
   Note that _IO_off_t must be an integral type. */

/* _IO_pos_BAD is an _IO_fpos_t value indicating error, unknown, or EOF. */
#ifndef _IO_pos_BAD
#define _IO_pos_BAD ((_IO_fpos_t)(-1))
#endif
/* _IO_pos_as_off converts an _IO_fpos_t value to an _IO_off_t value. */
#ifndef _IO_pos_as_off
#define _IO_pos_as_off(__pos) ((_IO_off_t)(__pos))
#endif
/* _IO_pos_adjust adjust an _IO_fpos_t by some number of bytes. */
#ifndef _IO_pos_adjust
#define _IO_pos_adjust(__pos, __delta) ((__pos) += (__delta))
#endif
/* _IO_pos_0 is an _IO_fpos_t value indicating beginning of file. */
#ifndef _IO_pos_0
#define _IO_pos_0 ((_IO_fpos_t)0)
#endif

#ifdef __cplusplus
}
#endif

#if  _IO_UNIFIED_JUMPTABLES
#define _IO_FJUMP /* nothing */
#else
#define _IO_FJUMP &_IO_file_jumps,
#endif
#ifdef _IO_MTSAFE_IO
/* check following! */
#define FILEBUF_LITERAL(CHAIN, FLAGS, FD) \
       { _IO_MAGIC+_IO_LINKED+_IO_IS_FILEBUF+FLAGS, \
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, CHAIN, _IO_FJUMP FD, \
	   0, 0, 0, 0, { 0 }, &_IO_stdfile_##FD##_lock }
#else
/* check following! */
#define FILEBUF_LITERAL(CHAIN, FLAGS, FD) \
       { _IO_MAGIC+_IO_LINKED+_IO_IS_FILEBUF+FLAGS, \
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, CHAIN, _IO_FJUMP FD }
#endif

/* VTABLE_LABEL defines NAME as of the CLASS class.
   CNLENGTH is strlen(#CLASS).  */
#ifdef __GNUC__
#if _G_VTABLE_LABEL_HAS_LENGTH
#define VTABLE_LABEL(NAME, CLASS, CNLENGTH) \
  extern char NAME[] asm (_G_VTABLE_LABEL_PREFIX #CNLENGTH #CLASS);
#else
#define VTABLE_LABEL(NAME, CLASS, CNLENGTH) \
  extern char NAME[] asm (_G_VTABLE_LABEL_PREFIX #CLASS);
#endif
#endif /* __GNUC__ */

#if !defined(builtinbuf_vtable) && defined(__cplusplus)
#ifdef __GNUC__
VTABLE_LABEL(builtinbuf_vtable, builtinbuf, 10)
#else
#if _G_VTABLE_LABEL_HAS_LENGTH
#define builtinbuf_vtable _G_VTABLE_LABEL_PREFIX_ID##10builtinbuf
#else
#define builtinbuf_vtable _G_VTABLE_LABEL_PREFIX_ID##builtinbuf
#endif
#endif
#endif /* !defined(builtinbuf_vtable) && defined(__cplusplus) */

#if defined(__STDC__) || defined(__cplusplus)
#define _IO_va_start(args, last) va_start(args, last)
#else
#define _IO_va_start(args, last) va_start(args)
#endif

extern struct _IO_fake_stdiobuf _IO_stdin_buf, _IO_stdout_buf, _IO_stderr_buf;

#if 1
#define COERCE_FILE(FILE) /* Nothing */
#else
/* This is part of the kludge for binary compatibility with old stdio. */
#define COERCE_FILE(FILE) \
  (((FILE)->_IO_file_flags & _IO_MAGIC_MASK) == _OLD_MAGIC_MASK \
    && (FILE) = *(FILE**)&((int*)fp)[1])
#endif

#ifdef EINVAL
#define MAYBE_SET_EINVAL __set_errno (EINVAL)
#else
#define MAYBE_SET_EINVAL /* nothing */
#endif

#ifdef DEBUG
#define CHECK_FILE(FILE,RET) \
	if ((FILE) == NULL) { MAYBE_SET_EINVAL; return RET; } \
	else { COERCE_FILE(FILE); \
	       if (((FILE)->_IO_file_flags & _IO_MAGIC_MASK) != _IO_MAGIC) \
	  { errno = EINVAL; return RET; }}
#else
#define CHECK_FILE(FILE,RET) \
	COERCE_FILE(FILE)
#endif
