#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static int sig;

static int
f (void *a)
{
  puts ("in f");
  union sigval sival;
  sival.sival_int = getpid ();
  printf ("pid = %d\n", sival.sival_int);
  if (sigqueue (getppid (), sig, sival) != 0)
    return 1;
  return 0;
}


static int
do_test (void)
{
  int mypid = getpid ();

  sig = SIGRTMIN;
  sigset_t ss;
  sigemptyset (&ss);
  sigaddset (&ss, sig);
  if (sigprocmask (SIG_BLOCK, &ss, NULL) != 0)
    {
      printf ("sigprocmask failed: %m\n");
      return 1;
    }

  char st[128 * 1024];
  pid_t p = clone (f, st + sizeof (st), 0, 0);
  if (p == -1)
    {
      printf("clone failed: %m\n");
      return 1;
    }
  printf ("new thread: %d\n", (int) p);

  siginfo_t si;
  do
    if (sigwaitinfo (&ss, &si) < 0)
      {
	printf("sigwaitinfo failed: %m\n");
	kill (p, SIGKILL);
	return 1;
      }
  while  (si.si_signo != sig || si.si_code != SI_QUEUE);

  if (si.si_int != (int) p)
    {
      printf ("expected PID %d, got si_int %d\n", (int) p, si.si_int);
      kill (p, SIGKILL);
      return 1;
    }

  if (si.si_pid != p)
    {
      printf ("expected PID %d, got si_pid %d\n", (int) p, (int) si.si_pid);
      kill (p, SIGKILL);
      return 1;
    }

  int e;
  if (waitpid (p, &e, __WCLONE) != p)
    {
      puts ("waitpid failed");
      kill (p, SIGKILL);
      return 1;
    }
  if (!WIFEXITED (e))
    {
      puts ("did not terminate correctly");
      return 1;
    }
  if (WEXITSTATUS (e) != 0)
    {
      printf ("exit code %d\n", WEXITSTATUS (e));
      return 1;
    }

  if (getpid () != mypid)
    {
      puts ("my PID changed");
      return 1;
    }

  return 0;
}

#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"
