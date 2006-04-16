/* Determine protocol families for which interfaces exist.  Linux version.
   Copyright (C) 2003, 2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <not-cancel.h>
#include <kernel-features.h>


#ifndef IFA_F_TEMPORARY
# define IFA_F_TEMPORARY IFA_F_SECONDARY
#endif


static int
make_request (int fd, pid_t pid, bool *seen_ipv4, bool *seen_ipv6,
	      struct in6addrinfo **in6ai, size_t *in6ailen)
{
  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;
  struct sockaddr_nl nladdr;

  req.nlh.nlmsg_len = sizeof (req);
  req.nlh.nlmsg_type = RTM_GETADDR;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = time (NULL);
  req.g.rtgen_family = AF_UNSPEC;

  memset (&nladdr, '\0', sizeof (nladdr));
  nladdr.nl_family = AF_NETLINK;

  if (TEMP_FAILURE_RETRY (__sendto (fd, (void *) &req, sizeof (req), 0,
				    (struct sockaddr *) &nladdr,
				    sizeof (nladdr))) < 0)
    return -1;

  *seen_ipv4 = false;
  *seen_ipv6 = false;

  bool done = false;
  char buf[4096];
  struct iovec iov = { buf, sizeof (buf) };
  struct in6ailist
  {
    struct in6addrinfo info;
    struct in6ailist *next;
  } *in6ailist = NULL;
  size_t in6ailistlen = 0;

  do
    {
      struct msghdr msg =
	{
	  (void *) &nladdr, sizeof (nladdr),
	  &iov, 1,
	  NULL, 0,
	  0
	};

      ssize_t read_len = TEMP_FAILURE_RETRY (__recvmsg (fd, &msg, 0));
      if (read_len < 0)
	return -1;

      if (msg.msg_flags & MSG_TRUNC)
	return -1;

      struct nlmsghdr *nlmh;
      for (nlmh = (struct nlmsghdr *) buf;
	   NLMSG_OK (nlmh, (size_t) read_len);
	   nlmh = (struct nlmsghdr *) NLMSG_NEXT (nlmh, read_len))
	{
	  if (nladdr.nl_pid != 0 || (pid_t) nlmh->nlmsg_pid != pid
	      || nlmh->nlmsg_seq != req.nlh.nlmsg_seq)
	    continue;

	  if (nlmh->nlmsg_type == RTM_NEWADDR)
	    {
	      struct ifaddrmsg *ifam = (struct ifaddrmsg *) NLMSG_DATA (nlmh);

	      switch (ifam->ifa_family)
		{
		case AF_INET:
		  *seen_ipv4 = true;
		  break;
		case AF_INET6:
		  *seen_ipv6 = true;

		  if (ifam->ifa_flags & (IFA_F_DEPRECATED | IFA_F_TEMPORARY))
		    {
		      struct rtattr *rta = IFA_RTA (ifam);
		      size_t len = (nlmh->nlmsg_len
				    - NLMSG_LENGTH (sizeof (*ifam)));
		      void *local = NULL;
		      void *address = NULL;
		      while (RTA_OK (rta, len))
			{
			  switch (rta->rta_type)
			    {
			    case IFA_LOCAL:
			      local = RTA_DATA (rta);
			      break;

			    case IFA_ADDRESS:
			      address = RTA_DATA (ta);
			      break;
			    }

			  rta = RTA_NEXT (rta, len);
			}

		      struct in6ailist *newp = alloca (sizeof (*newp));
		      newp->info.flags = (((ifam->ifa_flags & IFA_F_DEPRECATED)
					   ? in6ai_deprecated : 0)
					  | ((ifam->ifa_flags
					      & IFA_F_TEMPORARY)
					     ? in6ai_temporary : 0));
		      memcpy (newp->info.addr, address ?: local,
			      sizeof (newp->info.addr));
		      newp->next = in6ailist;
		      in6ailsit = newp;
		      ++in6ailistlen;
		    }
		  break;
		default:
		  /* Ignore.  */
		  break;
		}
	    }
	  else if (nlmh->nlmsg_type == NLMSG_DONE)
	    /* We found the end, leave the loop.  */
	    done = true;
	}
    }
  while (! done);

  close_not_cancel_no_status (fd);

  if (in6ailist != NULL)
    {
      *in6ai = malloc (in6ailistlen * sizeof (**in6ai));
      if (*in6ai == NULL)
	return -1;

      *in6ailen = in6ailistlen;

      do
	{
	  (*in6ai)[--in6ailistlen] = in6ailist->info;
	  in6ailist = in6ailist->next;
	}
      while (in6ailist != NULL);
    }

  return 0;
}


/* We don't know if we have NETLINK support compiled in in our
   Kernel.  */
#if __ASSUME_NETLINK_SUPPORT == 0
/* Define in ifaddrs.h.  */
extern int __no_netlink_support attribute_hidden;
#else
# define __no_netlink_support 0
#endif


void
attribute_hidden
__check_pf (bool *seen_ipv4, bool *seen_ipv6,
	    struct in6addrinfo **in6ai, size_t *in6ailen)
{
  *in6ai = NULL;
  *in6ailen = 0;

  if (! __no_netlink_support)
    {
      int fd = __socket (PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

      struct sockaddr_nl nladdr;
      memset (&nladdr, '\0', sizeof (nladdr));
      nladdr.nl_family = AF_NETLINK;

      socklen_t addr_len = sizeof (nladdr);

      if (fd >= 0
	  && __bind (fd, (struct sockaddr *) &nladdr, sizeof (nladdr)) == 0
	  && __getsockname (fd, (struct sockaddr *) &nladdr, &addr_len) == 0
	  && make_request (fd, nladdr.nl_pid, seen_ipv4, seen_ipv6,
			   in6ai, in6ailen) == 0)
	/* It worked.  */
	return;

      if (fd >= 0)
	__close (fd);

#if __ASSUME_NETLINK_SUPPORT == 0
      /* Remember that there is no netlink support.  */
      __no_netlink_support = 1;
#else
      /* We cannot determine what interfaces are available.  Be
	 pessimistic.  */
      *seen_ipv4 = true;
      *seen_ipv6 = true;
#endif
    }

#if __ASSUME_NETLINK_SUPPORT == 0
  /* No netlink.  Get the interface list via getifaddrs.  */
  struct ifaddrs *ifa = NULL;
  if (getifaddrs (&ifa) != 0)
    {
      /* We cannot determine what interfaces are available.  Be
	 pessimistic.  */
      *seen_ipv4 = true;
      *seen_ipv6 = true;
      return;
    }

  struct ifaddrs *runp;
  for (runp = ifa; runp != NULL; runp = runp->ifa_next)
    if (runp->ifa_addr->sa_family == PF_INET)
      *seen_ipv4 = true;
    else if (runp->ifa_addr->sa_family == PF_INET6)
      *seen_ipv6 = true;

  (void) freeifaddrs (ifa);
#endif
}
