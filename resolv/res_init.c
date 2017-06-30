/* Resolver state initialization and resolv.conf parsing.
   Copyright (C) 1995-2017 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <ctype.h>
#include <netdb.h>
#include <resolv/resolv-internal.h>
#include <res_hconf.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <inet/net-internal.h>
#include <errno.h>
#include <resolv_conf.h>

static void res_setoptions (res_state, const char *);
static uint32_t net_mask (struct in_addr);

unsigned long long int __res_initstamp;

int
res_ninit (res_state statp)
{
  return __res_vinit (statp, 0);
}
libc_hidden_def (__res_ninit)

/* Return true if CH separates the netmask in the "sortlist"
   directive.  */
static inline bool
is_sort_mask (char ch)
{
  return ch == '/' || ch == '&';
}

/* Array of strings for the search array.  The backing store is
   managed separately.  */
#define DYNARRAY_STRUCT search_list
#define DYNARRAY_ELEMENT const char *
#define DYNARRAY_INITIAL_SIZE 4
#define DYNARRAY_PREFIX search_list_
#include <malloc/dynarray-skeleton.c>

/* resolv.conf parser state and results.  */
struct resolv_conf_parser
{
  char *buffer;            /* Temporary buffer for reading lines.  */
  char *search_list_store; /* Backing storage for search list entries.  */
  struct search_list search_list; /* Points into search_list_store.  */
};

static void
resolv_conf_parser_init (struct resolv_conf_parser *parser)
{
  parser->buffer = NULL;
  parser->search_list_store = NULL;
  search_list_init (&parser->search_list);
}

static void
resolv_conf_parser_free (struct resolv_conf_parser *parser)
{
  free (parser->buffer);
  free (parser->search_list_store);
  search_list_free (&parser->search_list);
}

/* Try to obtain the domain name from the host name and store it in
   *RESULT.  Return false on memory allocation failure.  If the domain
   name cannot be determined for any other reason, write NULL to
   *RESULT and return true.  */
static bool
domain_from_hostname (char **result)
{
  char buf[256];
  /* gethostbyname may not terminate the buffer.  */
  buf[sizeof (buf) - 1] = '\0';
  if (__gethostname (buf, sizeof (buf) - 1) == 0)
    {
      char *dot = strchr (buf, '.');
      if (dot != NULL)
        {
          *result = __strdup (dot + 1);
          if (*result == NULL)
            return false;
          return true;
        }
    }
  *result = NULL;
  return true;
}

/* Internal helper function for __res_vinit, to aid with resource
   deallocation and error handling.  Return true on success, false on
   failure.  */
static bool
res_vinit_1 (res_state statp, bool preinit, FILE *fp,
             struct resolv_conf_parser *parser)
{
  char *cp;
  size_t buffer_size = 0;
  int nserv = 0;    /* Number of nameservers read from file.  */
  bool have_serv6 = false;
  bool haveenv = false;
  int nsort = 0;
  char *net;

  if (!preinit)
    {
      statp->retrans = RES_TIMEOUT;
      statp->retry = RES_DFLRETRY;
      statp->options = RES_DEFAULT;
      statp->id = res_randomid ();
    }

  statp->nscount = 0;
  statp->defdname[0] = '\0';
  statp->ndots = 1;
  statp->pfcode = 0;
  statp->_vcsock = -1;
  statp->_flags = 0;
  statp->__glibc_unused_qhook = NULL;
  statp->__glibc_unused_rhook = NULL;
  statp->_u._ext.nscount = 0;
  for (int n = 0; n < MAXNS; n++)
    statp->_u._ext.nsaddrs[n] = NULL;

  /* Allow user to override the local domain definition.  */
  if ((cp = getenv ("LOCALDOMAIN")) != NULL)
    {
      /* The code below splits the string in place.  */
      cp = __strdup (cp);
      if (cp == NULL)
        return false;
      free (parser->search_list_store);
      parser->search_list_store = cp;
      haveenv = true;

      /* The string will be truncated as needed below.  */
      search_list_add (&parser->search_list, cp);

      /* Set search list to be blank-separated strings from rest of
         env value.  Permits users of LOCALDOMAIN to still have a
         search list, and anyone to set the one that they want to use
         as an individual (even more important now that the rfc1535
         stuff restricts searches).  */
      for (bool in_name = true; *cp != '\0'; cp++)
        {
          if (*cp == '\n')
            {
              *cp = '\0';
              break;
            }
          else if (*cp == ' ' || *cp == '\t')
            {
              *cp = '\0';
              in_name = false;
            }
          else if (!in_name)
            {
              search_list_add (&parser->search_list, cp);
              in_name = true;
            }
        }
    }

#define MATCH(line, name)                       \
  (!strncmp ((line), name, sizeof (name) - 1)     \
   && ((line)[sizeof (name) - 1] == ' '           \
       || (line)[sizeof (name) - 1] == '\t'))

  if (fp != NULL)
    {
      /* No threads use this stream.  */
      __fsetlocking (fp, FSETLOCKING_BYCALLER);
      /* Read the config file.  */
      while (true)
        {
          {
            ssize_t ret = __getline (&parser->buffer, &buffer_size, fp);
            if (ret <= 0)
              {
                if (_IO_ferror_unlocked (fp))
                  return false;
                else
                  break;
              }
          }

          /* Skip comments.  */
          if (*parser->buffer == ';' || *parser->buffer == '#')
            continue;
          /* Read default domain name.  */
          if (MATCH (parser->buffer, "domain"))
            {
              if (haveenv)
                /* LOCALDOMAIN overrides the configuration file.  */
                continue;
              cp = parser->buffer + sizeof ("domain") - 1;
              while (*cp == ' ' || *cp == '\t')
                cp++;
              if ((*cp == '\0') || (*cp == '\n'))
                continue;

              cp = __strdup (cp);
              if (cp == NULL)
                return false;
              free (parser->search_list_store);
              parser->search_list_store = cp;
              search_list_clear (&parser->search_list);
              search_list_add (&parser->search_list, cp);
              /* Replace trailing whitespace.  */
              if ((cp = strpbrk (cp, " \t\n")) != NULL)
                *cp = '\0';
              continue;
            }
          /* Set search list.  */
          if (MATCH (parser->buffer, "search"))
            {
              if (haveenv)
                /* LOCALDOMAIN overrides the configuration file.  */
                continue;
              cp = parser->buffer + sizeof ("search") - 1;
              while (*cp == ' ' || *cp == '\t')
                cp++;
              if ((*cp == '\0') || (*cp == '\n'))
                continue;

              {
                char *p = strchr (cp, '\n');
                if (p != NULL)
                  *p = '\0';
              }
              cp = __strdup (cp);
              if (cp == NULL)
                return false;
              free (parser->search_list_store);
              parser->search_list_store = cp;

              /* The string is truncated below.  */
              search_list_clear (&parser->search_list);
              search_list_add (&parser->search_list, cp);

              /* Set search list to be blank-separated strings on rest
                 of line.  */
              for (bool in_name = true; *cp != '\0'; cp++)
                {
                  if (*cp == ' ' || *cp == '\t')
                    {
                      *cp = '\0';
                      in_name = false;
                    }
                  else if (!in_name)
                    {
                      search_list_add (&parser->search_list, cp);
                      in_name = true;
                    }
                }
              continue;
            }
          /* Read nameservers to query.  */
          if (MATCH (parser->buffer, "nameserver") && nserv < MAXNS)
            {
              struct in_addr a;

              cp = parser->buffer + sizeof ("nameserver") - 1;
              while (*cp == ' ' || *cp == '\t')
                cp++;
              if ((*cp != '\0') && (*cp != '\n') && __inet_aton (cp, &a))
                {
                  statp->nsaddr_list[nserv].sin_addr = a;
                  statp->nsaddr_list[nserv].sin_family = AF_INET;
                  statp->nsaddr_list[nserv].sin_port = htons (NAMESERVER_PORT);
                  nserv++;
                }
              else
                {
                  struct in6_addr a6;
                  char *el;

                  if ((el = strpbrk (cp, " \t\n")) != NULL)
                    *el = '\0';
                  if ((el = strchr (cp, SCOPE_DELIMITER)) != NULL)
                    *el = '\0';
                  if ((*cp != '\0') && (__inet_pton (AF_INET6, cp, &a6) > 0))
                    {
                      struct sockaddr_in6 *sa6;

                      sa6 = malloc (sizeof (*sa6));
                      if (sa6 == NULL)
                        return false;

                      sa6->sin6_family = AF_INET6;
                      sa6->sin6_port = htons (NAMESERVER_PORT);
                      sa6->sin6_flowinfo = 0;
                      sa6->sin6_addr = a6;

                      sa6->sin6_scope_id = 0;
                      if (__glibc_likely (el != NULL))
                        /* Ignore errors, for backwards
                           compatibility.  */
                        __inet6_scopeid_pton
                          (&a6, el + 1, &sa6->sin6_scope_id);

                      statp->nsaddr_list[nserv].sin_family = 0;
                      statp->_u._ext.nsaddrs[nserv] = sa6;
                      statp->_u._ext.nssocks[nserv] = -1;
                      have_serv6 = true;
                      nserv++;
                    }
                }
              continue;
            }
          if (MATCH (parser->buffer, "sortlist"))
            {
              struct in_addr a;

              cp = parser->buffer + sizeof ("sortlist") - 1;
              while (nsort < MAXRESOLVSORT)
                {
                  while (*cp == ' ' || *cp == '\t')
                    cp++;
                  if (*cp == '\0' || *cp == '\n' || *cp == ';')
                    break;
                  net = cp;
                  while (*cp && !is_sort_mask (*cp) && *cp != ';'
                         && isascii (*cp) && !isspace (*cp))
                    cp++;
                  char separator = *cp;
                  *cp = 0;
                  if (__inet_aton (net, &a))
                    {
                      statp->sort_list[nsort].addr = a;
                      if (is_sort_mask (separator))
                        {
                          *cp++ = separator;
                          net = cp;
                          while (*cp && *cp != ';'
                                 && isascii (*cp) && !isspace (*cp))
                            cp++;
                          separator = *cp;
                          *cp = 0;
                          if (__inet_aton (net, &a))
                            statp->sort_list[nsort].mask = a.s_addr;
                          else
                            statp->sort_list[nsort].mask
                              = net_mask (statp->sort_list[nsort].addr);
                        }
                      else
                        statp->sort_list[nsort].mask
                          = net_mask (statp->sort_list[nsort].addr);
                      nsort++;
                    }
                  *cp = separator;
                }
              continue;
            }
          if (MATCH (parser->buffer, "options"))
            {
              res_setoptions (statp, parser->buffer + sizeof ("options") - 1);
              continue;
            }
        }
      statp->nscount = nserv;
      if (have_serv6)
        /* We try IPv6 servers again.  */
        statp->ipv6_unavail = false;
      statp->nsort = nsort;
      fclose (fp);
    }
  if (__glibc_unlikely (statp->nscount == 0))
    {
      statp->nsaddr.sin_addr = __inet_makeaddr (IN_LOOPBACKNET, 1);
      statp->nsaddr.sin_family = AF_INET;
      statp->nsaddr.sin_port = htons (NAMESERVER_PORT);
      statp->nscount = 1;
    }

  if (search_list_size (&parser->search_list) == 0)
    {
      char *domain;
      if (!domain_from_hostname (&domain))
        return false;
      if (domain != NULL)
        {
          free (parser->search_list_store);
          parser->search_list_store = domain;
          search_list_add (&parser->search_list, domain);
        }
    }

  if ((cp = getenv ("RES_OPTIONS")) != NULL)
    res_setoptions (statp, cp);

  if (search_list_has_failed (&parser->search_list))
    {
      __set_errno (ENOMEM);
      return false;
    }

  statp->options |= RES_INIT;
  return true;
}

/* Set up default settings.  If the /etc/resolv.conf configuration
   file exist, the values there will have precedence.  Otherwise, the
   server address is set to INADDR_LOOPBACK and the default domain
   name comes from gethostname.  The RES_OPTIONS and LOCALDOMAIN
   environment variables can be used to override some settings.
   Return 0 if completes successfully, -1 on error.  */
int
__res_vinit (res_state statp, int preinit)
{
  /* Ensure that /etc/hosts.conf has been loaded (once).  */
  _res_hconf_init ();

  FILE *fp = fopen (_PATH_RESCONF, "rce");
  if (fp == NULL)
    switch (errno)
      {
      case EACCES:
      case EISDIR:
      case ELOOP:
      case ENOENT:
      case ENOTDIR:
      case EPERM:
        /* Ignore these errors.  They are persistent errors caused
           by file system contents.  */
        break;
      default:
        /* Other errors refer to resource allocation problems and
           need to be handled by the application.  */
        return -1;
      }

  struct resolv_conf_parser parser;
  resolv_conf_parser_init (&parser);
  bool ok = res_vinit_1 (statp, preinit, fp, &parser);

  if (ok)
    {
      struct resolv_conf init =
        {
          .search_list = search_list_begin (&parser.search_list),
          .search_list_size = search_list_size (&parser.search_list),
        };
      struct resolv_conf *conf = __resolv_conf_allocate (&init);
      if (conf == NULL)
        ok = false;
      else
        {
          ok = __resolv_conf_attach (statp, conf);
          __resolv_conf_put (conf);
        }
    }
  resolv_conf_parser_free (&parser);

  if (!ok)
    {
      /* Deallocate the name server addresses which have been
         allocated.  */
      for (int n = 0; n < MAXNS; n++)
        free (statp->_u._ext.nsaddrs[n]);
      return -1;
    }
  return 0;
}

static void
res_setoptions (res_state statp, const char *options)
{
  const char *cp = options;

  while (*cp)
    {
      /* Skip leading and inner runs of spaces.  */
      while (*cp == ' ' || *cp == '\t')
        cp++;
      /* Search for and process individual options.  */
      if (!strncmp (cp, "ndots:", sizeof ("ndots:") - 1))
        {
          int i = atoi (cp + sizeof ("ndots:") - 1);
          if (i <= RES_MAXNDOTS)
            statp->ndots = i;
          else
            statp->ndots = RES_MAXNDOTS;
        }
      else if (!strncmp (cp, "timeout:", sizeof ("timeout:") - 1))
        {
          int i = atoi (cp + sizeof ("timeout:") - 1);
          if (i <= RES_MAXRETRANS)
            statp->retrans = i;
          else
            statp->retrans = RES_MAXRETRANS;
        }
      else if (!strncmp (cp, "attempts:", sizeof ("attempts:") - 1))
        {
          int i = atoi (cp + sizeof ("attempts:") - 1);
          if (i <= RES_MAXRETRY)
            statp->retry = i;
          else
            statp->retry = RES_MAXRETRY;
        }
      else
        {
          static const struct
          {
            char str[22];
            uint8_t len;
            uint8_t clear;
            unsigned long int flag;
          } options[] = {
#define STRnLEN(str) str, sizeof (str) - 1
            { STRnLEN ("inet6"), 0, DEPRECATED_RES_USE_INET6 },
            { STRnLEN ("rotate"), 0, RES_ROTATE },
            { STRnLEN ("edns0"), 0, RES_USE_EDNS0 },
            { STRnLEN ("single-request-reopen"), 0, RES_SNGLKUPREOP },
            { STRnLEN ("single-request"), 0, RES_SNGLKUP },
            { STRnLEN ("no_tld_query"), 0, RES_NOTLDQUERY },
            { STRnLEN ("no-tld-query"), 0, RES_NOTLDQUERY },
            { STRnLEN ("use-vc"), 0, RES_USEVC }
          };
#define noptions (sizeof (options) / sizeof (options[0]))
          for (int i = 0; i < noptions; ++i)
            if (strncmp (cp, options[i].str, options[i].len) == 0)
              {
                if (options[i].clear)
                  statp->options &= options[i].flag;
                else
                  statp->options |= options[i].flag;
                break;
              }
        }
      /* Skip to next run of spaces.  */
      while (*cp && *cp != ' ' && *cp != '\t')
        cp++;
    }
}

static uint32_t
net_mask (struct in_addr in)
{
  uint32_t i = ntohl (in.s_addr);

  if (IN_CLASSA (i))
    return htonl (IN_CLASSA_NET);
  else if (IN_CLASSB (i))
    return htonl (IN_CLASSB_NET);
  return htonl (IN_CLASSC_NET);
}
