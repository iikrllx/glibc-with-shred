/* Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#ifndef _NET_IF_H

#define _NET_IF_H	1
#include <features.h>

#include <sys/types.h>
#include <sys/socket.h>

/* Standard interface flags. */
enum
  {
    IFF_UP = 0x1,		/* Interface is up.  */
    IFF_BROADCAST = 0x2,	/* Broadcast address valid.  */
    IFF_DEBUG = 0x4,		/* Turn on debugging.  */
    IFF_LOOPBACK = 0x8,		/* Is a loopback net.  */
    IFF_POINTOPOINT = 0x10,	/* Interface is point-to-point link.  */
    IFF_NOTRAILERS = 0x20,	/* Avoid use of trailers.  */
    IFF_RUNNING = 0x40,		/* Resources allocated.  */
    IFF_NOARP = 0x80,		/* No address resolution protocol.  */
    IFF_PROMISC = 0x100,	/* Receive all packets.  */
    /* Not supported */
    IFF_ALLMULTI = 0x200,	/* Receive all multicast packets.  */

    IFF_MASTER = 0x400,		/* Master of a load balancer.  */
    IFF_SLAVE = 0x800,		/* Slave of a load balancer.  */

    IFF_MULTICAST = 0x1000	/* Supports multicast.  */
  };

/* The ifaddr structure contains information about one address of an
   interface.  They are maintained by the different address families,
   are allocated and attached when an address is set, and are linked
   together so all addresses for an interface can be located.  */

struct ifaddr
  {
    struct sockaddr ifa_addr;	/* Address of interface.  */
    union
      {
	struct sockaddr	ifu_broadaddr;
	struct sockaddr	ifu_dstaddr;
      } ifa_ifu;
    struct iface *ifa_ifp;	/* Back-pointer to interface.  */
    struct ifaddr *ifa_next;	/* Next address for interface.  */
  };

#define	ifa_broadaddr	ifa_ifu.ifu_broadaddr	/* broadcast address	*/
#define	ifa_dstaddr	ifa_ifu.ifu_dstaddr	/* other end of link	*/

/* Device mapping structure. I'd just gone off and designed a
   beautiful scheme using only loadable modules with arguments for
   driver options and along come the PCMCIA people 8)

   Ah well. The get() side of this is good for WDSETUP, and it'll be
   handy for debugging things. The set side is fine for now and being
   very small might be worth keeping for clean configuration.  */

struct ifmap
  {
    unsigned long int mem_start;
    unsigned long int mem_end;
    unsigned short int base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
    /* 3 bytes spare */
  };

/* Interface request structure used for socket ioctl's.  All interface
   ioctl's must have parameter definitions which begin with ifr_name.
   The remainder may be interface specific.  */

struct ifreq
  {
#define IFHWADDRLEN	6
#define	IFNAMSIZ	16
    union
      {
	char ifrn_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
      } ifr_ifrn;

    union
      {
	struct sockaddr ifru_addr;
	struct sockaddr ifru_dstaddr;
	struct sockaddr ifru_broadaddr;
	struct sockaddr ifru_netmask;
	struct sockaddr ifru_hwaddr;
	short int ifru_flags;
	int ifru_metric;
	int ifru_mtu;
	struct ifmap ifru_map;
	char ifru_slave[IFNAMSIZ];	/* Just fits the size */
	__caddr_t ifru_data;
      } ifr_ifru;
  };

#define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
#define ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address 		*/
#define	ifr_addr	ifr_ifru.ifru_addr	/* address		*/
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-p lnk	*/
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address	*/
#define	ifr_netmask	ifr_ifru.ifru_netmask	/* interface net mask	*/
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags		*/
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric		*/
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu			*/
#define ifr_map		ifr_ifru.ifru_map	/* device map		*/
#define ifr_slave	ifr_ifru.ifru_slave	/* slave device		*/
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface	*/


/* Structure used in SIOCGIFCONF request.  Used to retrieve interface
   configuration for machine (useful for programs which must know all
   networks accessible).  */

struct ifconf
  {
    int	ifc_len;			/* Size of buffer.  */
    union
      {
	__caddr_t ifcu_buf;
	struct ifreq *ifcu_req;
      } ifc_ifcu;
  };
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* Buffer address.  */
#define	ifc_req	ifc_ifcu.ifcu_req	/* Array of structures.  */

#endif /* net/if.h */
