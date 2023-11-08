/* unlinkat with shred files
 * fill file with zeroes before delete. security recover files.
 * shred is not effective for AIX, JFS, NFS, ReiserFS, XFS, Ext3, etc. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <shred-common.h>

char *
readselflink (int fd)
{
  char self_fd[24];    /* max possible length /proc/32768/fd/1024 - 19 */
  char buf[PATH_MAX];  /* maximum number of bytes as a pathname */
  ssize_t cb;
  char *s;

  sprintf (self_fd, "/proc/%d/fd/%d", getpid(), fd);

  if ((cb = readlink (self_fd, buf, sizeof (buf))) < 0)
    abort();

  buf[cb] = '\0';

  s = malloc ((strlen (buf) + 1) * sizeof (char));
  if (!s)
    abort ();

  strcpy (s, buf);
  return s;
}

void
dopass (const char *name)
{
  const char *self = "/proc/self/fd";
  const char *fn;
  struct dirent *dp;
  struct stat st;
  DIR *dir;
  int nfd;

  /* work only with regular files
   * other file types take a lot of time on shred */
  if (!(lstat (name, &st))
      && S_ISREG (st.st_mode) && !S_ISLNK (st.st_mode)
      && st.st_size && st.st_nlink == 1)
    {
      dir = opendir (self);
      if (!dir)
        abort ();

      /* check '/tmp' files. avoid this
       * system scripts that use 'cat' create files with zeros
       *
       * cat << EOF > /etc/kernel/postint.d/vboxadd
       * body
       * EOF
       *
       * vboxadd file will be with zeros
       * 'cat' will 'dup2' fds to stdin, stdout after 'unlinkat' syscall (look strace) */
      while ((dp = readdir (dir)) != NULL)
        {
          fn = dp -> d_name; /* ignore '.' '..' directories */
          if ((strcmp (fn, ".") == 0) || (strcmp (fn, "..") == 0))
            continue;

          char *filep = readselflink (atoi(fn));

          char dirname[8] = {0};
          strncpy (dirname, filep, strlen ("/tmp"));

          /* avoid shred temporary, locale files */
          if (strcmp (dirname, "/tmp") == 0)
            {
              if (closedir (dir))
                abort ();

              free (filep);
              return;
            }

          free (filep);
        }

      nfd = open (name, O_WRONLY | O_NOCTTY);
      if (nfd > 0)
        {
          /* work like $ shred -zn 0 <FILE>
           * fill file with zeroes
           * then unlinkat */
          shred (nfd, st.st_size);
          if (close (nfd))
            abort ();
        }

      if (closedir (dir))
        abort ();
    }
}

/* Remove the link named NAME.  */
int
__unlinkat (int fd, const char *name, int flag)
{
  /* initramfs often has 'init' variable
   * not run shred code to avoid Kernel panic problems */
  if (!getenv("init"))
    {
      if (flag != AT_REMOVEDIR)
        {
          bool sopattern = false;
          const char *so = ".so";
          int a, b;

          /* ignore *.so* files (shared libraries)
           * there is no need to shred them (system fail because dpkg tricks ..
           * -> *.dpkg-tmp *.dpkg-new *.dpkg-old files) */
          for (a = 0; name[a] != '\0'; a++)
            {
              for (b = 0; so[b] != '\0'; b++)
                {
                  if (name[a] == so[b])
                    {
                      a++;
                      continue;
                    }

                  a-=b;
                  b = 0;
                  break;
                }

                if (b == strlen (so))
                  {
                    sopattern = true;
                    break;
                  }
            }

          if (!sopattern && name != NULL)
            {
              /* without fd number
               * the pathname is interpreted relative to the current working
               * directory of the calling process */
              if (fd == AT_FDCWD)
                dopass (name);

              /* in this case fd link to directory path
               * example:
               * $ mkdir dir/; echo a > dir/a; echo b > dir/b
               * $ rm -r dir/
               * fd -> /path/to/dir/
               * name -> a (only basename)
               * we concatenate these values to absolute path */
              if (fd != AT_FDCWD)
                {
                  char *dirp = readselflink (fd);

                  char *pathname = malloc ((strlen (dirp) + strlen (name) + 2) * sizeof (char));
                  if (!pathname)
                    abort ();

                  sprintf (pathname, "%s/%s", dirp, name);
                  dopass (pathname);
                  free (pathname);
                  free (dirp);
                }
            }
        }
    }

  return INLINE_SYSCALL (unlinkat, 3, fd, name, flag);
}

weak_alias (__unlinkat, unlinkat)
