/* Copyright (C) 1997, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by H.J. Lu <hjl@gnu.ai.mit.edu>, 1997.

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

#ifdef USE_NSCD
# define inet_aton __inet_aton
#endif

  /*
   * disallow names consisting only of digits/dots, unless
   * they end in a dot.
   */
  if (isdigit (name[0]) || (isxdigit (name[0]) || name[0] == ':'))
    {
      const char *cp;
      char *hostname;
      typedef unsigned char host_addr_t[16];
      host_addr_t *host_addr;
      typedef char *host_addr_list_t[2];
      host_addr_list_t *h_addr_ptrs;
      char **h_alias_ptr;
      size_t size_needed;
      int addr_size;
#ifdef HAVE_TYPE
      int af = type;
#else
# ifndef HAVE_AF
      int af = -1;
# endif
#endif

      switch (af)
	{
	case AF_INET:
	  addr_size = INADDRSZ;
	  break;

	case AF_INET6:
	  addr_size = IN6ADDRSZ;
	  break;

	default:
#ifdef HAVE_TYPE
	  /* This must not happen.  */
	  *h_errnop = HOST_NOT_FOUND;
	  goto done;
#else
	  af = (_res.options & RES_USE_INET6) ? AF_INET6 : AF_INET;
	  addr_size = af == AF_INET6 ? IN6ADDRSZ : INADDRSZ;
	  break;
#endif
	}

      size_needed = (sizeof (*host_addr)
		     + sizeof (*h_addr_ptrs) + strlen (name) + 1);

#ifdef HAVE_LOOKUP_BUFFER
      if (buflen < size_needed)
	{
# ifdef NEED_H_ERRNO
	  *h_errnop = TRY_AGAIN;
# endif
	  __set_errno (ERANGE);
	  goto done;
	}
#else
      if (buffer_size < size_needed)
	{
	  char *new_buf;
	  buffer_size = size_needed;
	  new_buf = realloc (buffer, buffer_size);

	  if (new_buf == NULL)
	    {
	      save = errno;
	      free (buffer);
	      buffer = NULL;
	      buffer_size = 0;
	      __set_errno (save);
# ifdef NEED_H_ERRNO
	      *h_errnop = TRY_AGAIN;
# endif
	      result = (struct hostent *) NULL;
	      goto done;
	    }
	  buffer = new_buf;
	}
#endif /* HAVE_LOOKUP_BUFFER */

      memset (buffer, 0, size_needed);

      host_addr = (host_addr_t *) buffer;
      h_addr_ptrs = (host_addr_list_t *)
	((char *) host_addr + sizeof (*host_addr));
      h_alias_ptr = (char **) ((char *) h_addr_ptrs + sizeof (*h_addr_ptrs));
      hostname = (char *) h_alias_ptr + sizeof (*h_alias_ptr);

      if (isdigit (name[0]))
	{
	  for (cp = name;; ++cp)
	    {
	      if (!*cp)
		{
		  int ok;

		  if (*--cp == '.')
		    break;

		  /* All-numeric, no dot at the end. Fake up a hostent as if
		     we'd actually done a lookup.  What if someone types
		     255.255.255.255?  The test below will succeed
		     spuriously... ???  */
		  if (af == AF_INET)
		    ok = inet_aton (name, (struct in_addr *) host_addr);
		  else
		    {
		      assert (af == AF_INET6);
		      ok = (inet_pton (af, name, host_addr) > 0);
		    }
		  if (! ok)
		    {
		      *h_errnop = HOST_NOT_FOUND;
#ifndef HAVE_LOOKUP_BUFFER
		      result = (struct hostent *) NULL;
#endif
		      goto done;
		    }

		  resbuf.h_name = strcpy (hostname, name);
		  h_alias_ptr[0] = NULL;
		  resbuf.h_aliases = h_alias_ptr;
		  (*h_addr_ptrs)[0] = (char *)host_addr;
		  (*h_addr_ptrs)[1] = (char *)0;
		  resbuf.h_addr_list = *h_addr_ptrs;
		  if (
#ifdef HAVE_TYPE
		      type == AF_INET6
#else
		      af == AF_INET && (_res.options & RES_USE_INET6)
#endif
		      )
		    {
#ifdef HAVE_TYPE
		      if ((flags & AI_V4MAPPED) == 0)
			{
			  /* That's bad.  The user hasn't specified that she
			     allows IPv4 numeric addresses.  */
			  result = NULL;
			  *h_errnop = HOST_NOT_FOUND;
			  goto done;
			}
		      else
#endif
			{
			  /* We need to change the IP v4 address into the
			     IP v6 address.  */
			  char tmp[INADDRSZ], *p = (char *) host_addr;
			  int i;

			  /* Save a copy of the IP v4 address. */
			  memcpy (tmp, host_addr, INADDRSZ);
			  /* Mark this ipv6 addr as a mapped ipv4. */
			  for (i = 0; i < 10; i++)
			    *p++ = 0x00;
			  *p++ = 0xff;
			  *p++ = 0xff;
			  /* Copy the IP v4 address. */
			  memcpy (p, tmp, INADDRSZ);
			  resbuf.h_addrtype = AF_INET6;
			  resbuf.h_length = IN6ADDRSZ;
			}
		    }
		  else
		    {
		      resbuf.h_addrtype = af;
		      resbuf.h_length = addr_size;
		    }
		  *h_errnop = NETDB_SUCCESS;
#ifdef HAVE_LOOKUP_BUFFER
		  status = NSS_STATUS_SUCCESS;
#else
		  result = &resbuf;
#endif
		  goto done;
		}

	      if (!isdigit (*cp) && *cp != '.') break;
	    }
	}

      if ((isxdigit (name[0]) && strchr (name, ':') != NULL)
	  || name[0] == ':')
	{
	  const char *cp;
	  char *hostname;
	  typedef unsigned char host_addr_t [16];
	  host_addr_t *host_addr;
	  typedef char *host_addr_list_t [2];
	  host_addr_list_t *h_addr_ptrs;
	  size_t size_needed;
	  int addr_size;
#ifdef HAVE_TYPE
	  int af = type;
#else
# ifndef HAVE_AF
	  int af = -1;
# endif
#endif

	  switch (af)
	    {
	    default:
	      af = (_res.options & RES_USE_INET6) ? AF_INET6 : AF_INET;
	      if (af == AF_INET6)
		{
		  addr_size = IN6ADDRSZ;
		  break;
		}
	      /* FALLTHROUGH */

	    case AF_INET:
	      /* This is not possible.  We cannot represent an IPv6 address
		 in an `struct in_addr' variable.  */
	      *h_errnop = HOST_NOT_FOUND;
	      result = NULL;
	      goto done;

	    case AF_INET6:
	      addr_size = IN6ADDRSZ;
	      break;
	    }

	  size_needed = (sizeof (*host_addr)
			 + sizeof (*h_addr_ptrs) + strlen (name) + 1);

#ifdef HAVE_LOOKUP_BUFFER
	  if (buflen < size_needed)
	    {
# ifdef NEED_H_ERRNO
	      *h_errnop = TRY_AGAIN;
# endif
	      __set_errno (ERANGE);
	      goto done;
	    }
#else
	  if (buffer_size < size_needed)
	    {
	      char *new_buf;
	      buffer_size = size_needed;
	      new_buf = realloc (buffer, buffer_size);

	      if (new_buf == NULL)
		{
		  save = errno;
		  free (buffer);
		  __set_errno (save);
		  buffer = NULL;
		  buffer_size = 0;
		  result = (struct hostent *) NULL;
		  goto done;
		}
	      buffer = new_buf;
	    }
#endif /* HAVE_LOOKUP_BUFFER */

	  memset (buffer, 0, size_needed);

	  host_addr = (host_addr_t *) buffer;
	  h_addr_ptrs = (host_addr_list_t *)
	    ((char *) host_addr + sizeof (*host_addr));
	  hostname = (char *) h_addr_ptrs + sizeof (*h_addr_ptrs);

	  for (cp = name;; ++cp)
	    {
	      if (!*cp)
		{
		  if (*--cp == '.')
		    break;

		  /* All-IPv6-legal, no dot at the end. Fake up a
		     hostent as if we'd actually done a lookup.  */
		  if (inet_pton (AF_INET6, name, host_addr) <= 0)
		    {
		      *h_errnop = HOST_NOT_FOUND;
#ifndef HAVE_LOOKUP_BUFFER
		      result = (struct hostent *) NULL;
#endif
		      goto done;
		    }

		  resbuf.h_name = strcpy (hostname, name);
		  h_alias_ptr[0] = NULL;
		  resbuf.h_aliases = h_alias_ptr;
		  (*h_addr_ptrs)[0] = (char *) host_addr;
		  (*h_addr_ptrs)[1] = (char *) 0;
		  resbuf.h_addr_list = *h_addr_ptrs;
		  resbuf.h_addrtype = AF_INET6;
		  resbuf.h_length = addr_size;
		  *h_errnop = NETDB_SUCCESS;
#ifdef HAVE_LOOKUP_BUFFER
		  status = NSS_STATUS_SUCCESS;
#else
		  result = &resbuf;
#endif
		  goto done;
		}

	      if (!isxdigit (*cp) && *cp != ':' && *cp != '.') break;
	    }
	}
    }
