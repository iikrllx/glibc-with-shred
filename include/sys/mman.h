#ifndef _SYS_MMAN_H
#include <misc/sys/mman.h>

/* Now define the internal interfaces.  */
extern void *__mmap (void *__addr, size_t __len, int __prot,
		     int __flags, int __fd, __off_t __offset) __THROW;
extern void *__mmap64 (void *__addr, size_t __len, int __prot,
		       int __flags, int __fd, __off64_t __offset) __THROW;
extern int __munmap (void *__addr, size_t __len) __THROW;
extern int __mprotect (void *__addr, size_t __len, int __prot) __THROW;

/* This one is Linux specific.  */
extern void *__mremap (void *__addr, size_t __old_len,
		       size_t __new_len, int __may_move) __THROW;
#endif
