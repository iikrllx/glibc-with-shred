/* Tests for ttyname/ttyname_r with namespaces.
   Copyright (C) 2017-2023 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <https://www.gnu.org/licenses/>.  */

#include <sched.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <support/namespace.h>

#include "tst-ttyname-common.c"

static int
do_in_chroot_2 (int (*cb)(const char *, int))
{
  printf ("info:  entering chroot 2\n");

  int pid_pipe[2];
  xpipe (pid_pipe);
  int exit_pipe[2];
  xpipe (exit_pipe);

  /* Open the PTS that we'll be testing on.  */
  int master;
  char *slavename;
  VERIFY ((master = posix_openpt (O_RDWR|O_NOCTTY|O_NONBLOCK)) >= 0);
  VERIFY ((slavename = ptsname (master)));
  VERIFY (unlockpt (master) == 0);
  if (strncmp (slavename, "/dev/pts/", 9) != 0)
    FAIL_UNSUPPORTED ("slave pseudo-terminal is not under /dev/pts/: %s",
                      slavename);
  adjust_file_limit (slavename);
  /* wait until in a new mount ns to open the slave */

  /* enable `wait`ing on grandchildren */
  VERIFY (prctl (PR_SET_CHILD_SUBREAPER, 1) == 0);

  pid_t pid = xfork (); /* outer child */
  if (pid == 0)
    {
      xclose (master);
      xclose (pid_pipe[0]);
      xclose (exit_pipe[1]);

      if (!support_enter_mount_namespace ())
	FAIL_UNSUPPORTED ("could not enter new mount namespace");

      int slave = xopen (slavename, O_RDWR, 0);
      if (!doit (slave, "basic smoketest",
                 (struct result_r){.name=slavename, .ret=0, .err=0}))
        _exit (1);

      VERIFY (mount ("tmpfs", chrootdir, "tmpfs", 0, "mode=755") == 0);
      VERIFY (chdir (chrootdir) == 0);

      xmkdir ("proc", 0755);
      xmkdir ("dev", 0755);
      xmkdir ("dev/pts", 0755);

      VERIFY (mount ("devpts", "dev/pts", "devpts",
                     MS_NOSUID|MS_NOEXEC,
                     "newinstance,ptmxmode=0666,mode=620") == 0);
      VERIFY (symlink ("pts/ptmx", "dev/ptmx") == 0);

      touch ("console", 0);
      touch ("dev/console", 0);
      VERIFY (mount (slavename, "console", NULL, MS_BIND, NULL) == 0);

      xchroot (".");

      if (unshare (CLONE_NEWNS | CLONE_NEWPID) < 0)
        FAIL_UNSUPPORTED ("could not enter new PID namespace");
      pid = xfork (); /* inner child */
      if (pid == 0)
        {
          xclose (pid_pipe[1]);

          /* wait until the outer child has exited */
          char c;
          VERIFY (read (exit_pipe[0], &c, 1) == 0);
          xclose (exit_pipe[0]);

          VERIFY (mount ("proc", "/proc", "proc",
                         MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) == 0);

          char *linkname = xasprintf ("/proc/self/fd/%d", slave);
          char *target = proc_fd_readlink (linkname);
          VERIFY (strcmp (target, strrchr (slavename, '/')) == 0);
          free (linkname);

          _exit (cb (slavename, slave));
        }
      xwrite (pid_pipe[1], &pid, sizeof pid);
      _exit (0);
    }
  xclose (pid_pipe[1]);
  xclose (exit_pipe[0]);
  xclose (exit_pipe[1]);

  /* wait for the outer child */
  int status;
  xwaitpid (pid, &status, 0);
  VERIFY (WIFEXITED (status));
  int ret = WEXITSTATUS (status);
  if (ret != 0)
    return ret;

  /* set 'pid' to the inner child */
  VERIFY (read (pid_pipe[0], &pid, sizeof pid) == sizeof pid);
  xclose (pid_pipe[0]);

  /* wait for the inner child */
  xwaitpid (pid, &status, 0);
  VERIFY (WIFEXITED (status));
  xclose (master);
  return WEXITSTATUS (status);
}

static int
do_test (void)
{
  support_become_root ();

  do_in_chroot_2 (run_chroot_tests);

  return 0;
}

#include <support/test-driver.c>
