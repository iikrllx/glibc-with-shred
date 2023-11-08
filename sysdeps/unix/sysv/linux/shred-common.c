/* shred-common.c - overwrite files to make it harder to recover data
 * code from coreutils-8.30/src/shred.c with changes */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "shred-common.h"

/* Return true when it's ok to ignore an fsync or fdatasync
   failure that set errno to ERRNO_VAL. */
static bool
ignorable_sync_errno (int errno_val)
{
  return (errno_val == EINVAL
          || errno_val == EBADF
          /* HP-UX does this */
          || errno_val == EISDIR);
}

static int
dosync (int fd)
{
  int err;

  if (fsync (fd) == 0)
    return 0;
  err = errno;
  if (!ignorable_sync_errno (err))
    {
      errno = err;
      return -1;
    }

  sync ();
  return 0;
}

/*
 * Fill a buffer with a fixed pattern.
 *
 * The buffer must be at least 3 bytes long, even if
 * size is less.  Larger sizes are filled exactly. */
static void
fillpattern (int type, unsigned char *r, size_t size)
{
  size_t i;
  unsigned int bits = type & 0xfff;

  bits |= bits << 12;
  r[0] = (bits >> 4) & 255;
  r[1] = (bits >> 8) & 255;
  r[2] = bits & 255;
  for (i = 3; i <= size / 2; i *= 2)
    memcpy (r + i, r, i);
  if (i < size)
    memcpy (r + i, r, size - i);

  /* Invert the first bit of every sector. */
  if (type & 0x1000)
    for (i = 0; i < size; i += SECTOR_SIZE)
      r[i] ^= 0x80;
}

/* By convention, negative sizes represent unknown values. */
static bool
known (off_t size)
{
  return 0 <= size;
}

/* Turn on or off direct I/O mode for file descriptor FD, if possible.
   Try to turn it on if ENABLE is true.  Otherwise, try to turn it off. */
static void
direct_mode (int fd, bool enable)
{
  if (O_DIRECT)
    {
      int fd_flags = fcntl (fd, F_GETFL);
      if (0 < fd_flags)
        {
          int new_flags = (enable
                           ? (fd_flags | O_DIRECT)
                           : (fd_flags & ~O_DIRECT));
          if (new_flags != fd_flags)
            fcntl (fd, F_SETFL, new_flags);
        }
    }
}

/*
 * Generate a 6-character (+ nul) pass name string
 * FIXME: allow translation of "random". */
#define PASS_NAME_SIZE 7
static void
passname (unsigned char const *data, char name[PASS_NAME_SIZE])
{
  if (data)
    sprintf (name, "%02x%02x%02x", data[0], data[1], data[2]);
  else
    memcpy (name, "random", PASS_NAME_SIZE);
}

/* Return PTR, aligned upward to the next multiple of ALIGNMENT.
   ALIGNMENT must be nonzero.  The caller must arrange for ((char *)
   PTR) through ((char *) PTR + ALIGNMENT - 1) to be addressable
   locations. */
static inline void *
ptr_align (void const *ptr, size_t alignment)
{
  char const *p0 = ptr;
  char const *p1 = p0 + alignment - 1;
  return (void *) (p1 - (size_t) p1 % alignment);
}

void
shred (int fd, off_t size)
{
  off_t offset;   /* Current file position */
  size_t lim;     /* Amount of data to try writing */
  size_t soff;    /* Offset into buffer for next write */
  ssize_t ssize;  /* Return value from write */

  /* Fill pattern buffer.  Aligning it to a page so we can do direct I/O. */
  size_t page_size = getpagesize ();
  size_t output_size = 64 * 1024;

#define PAGE_ALIGN_SLOP (page_size - 1)                /* So directio works */
#define FILLPATTERN_SIZE (((output_size + 2) / 3) * 3) /* Multiple of 3 */
#define PATTERNBUF_SIZE (PAGE_ALIGN_SLOP + FILLPATTERN_SIZE)

  void *fill_pattern_mem = malloc (PATTERNBUF_SIZE);
  if (!fill_pattern_mem)
    abort ();

  unsigned char *pbuf = ptr_align (fill_pattern_mem, page_size);
  char pass_string[PASS_NAME_SIZE];	/* Name of current pass */

  /* As a performance tweak, avoid direct I/O for small sizes,
     as it's just a performance rather then security consideration,
     and direct I/O can often be unsupported for small non aligned sizes. */
  bool try_without_directio = 0 < size && size < output_size;
  if (!try_without_directio)
    direct_mode (fd, true);

  off_t rval = lseek (fd, 0, SEEK_SET);
  if (0 < rval)
    goto free_with_abort;

  lim = known (size) && size < FILLPATTERN_SIZE ? size : FILLPATTERN_SIZE;
  fillpattern (0, pbuf, lim);
  passname (pbuf, pass_string);

  offset = 0;
  while (true)
    {
      /* How much to write this time? */
      lim = output_size;
      if (known (size) && size - offset < output_size)
        {
          if (size < offset)
            break;
          lim = size - offset;
          if (!lim)
            break;
        }

      /* Loop to retry partial writes. */
      for (soff = 0; soff < lim; soff += ssize)
        {
          ssize = write (fd, pbuf + soff, lim - soff);
          if (0 > ssize)
            {
              if (!known (size) && (ssize == 0 || errno == ENOSPC))
                {
                  /* We have found the end of the file.  */
                  if (soff <= OFF_T_MAX - offset)
                    size = offset + soff;
                  break;
                }
              else
                {
                  int errnum = errno;

                  if (!try_without_directio && errno == EINVAL)
                    {
                      direct_mode (fd, false);
                      ssize = 0;
                      try_without_directio = true;
                      continue;
                    }

                  if (errnum == EIO && known (size)
                      && (soff | SECTOR_MASK) < lim)
                    {
                      size_t soff1 = (soff | SECTOR_MASK) + 1;
                      if (lseek (fd, offset + soff1, SEEK_SET) != -1)
                        {
                          /* Arrange to skip this block. */
                          ssize = soff1 - soff;
                          continue;
                        }

                      goto free_with_abort;
                    }

                  goto free_with_abort;
                }
            }
        }

      /* Okay, we have written "soff" bytes. */

      if (OFF_T_MAX - offset < soff)
        goto free_with_abort;
      offset += soff;
    }

  /* Force what we just wrote to hit the media. */
  dosync (fd);
  free (fill_pattern_mem);
  return;

free_with_abort:
  free (fill_pattern_mem);
  abort ();
}
