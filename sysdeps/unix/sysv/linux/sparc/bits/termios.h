/* termios type and macro definitions.  Linux/SPARC version.
   Copyright (C) 1993-2014 Free Software Foundation, Inc.
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

#ifndef _TERMIOS_H
# error "Never include <bits/termios.h> directly; use <termios.h> instead."
#endif

typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

#define NCCS 17
struct termios
  {
    tcflag_t c_iflag;		/* input mode flags */
    tcflag_t c_oflag;		/* output mode flags */
    tcflag_t c_cflag;		/* control mode flags */
    tcflag_t c_lflag;		/* local mode flags */
    cc_t c_line;		/* line discipline */
    cc_t c_cc[NCCS];		/* control characters */
  };

/* c_cc characters */
#define VINTR    0
#define VQUIT    1
#define VERASE   2
#define VKILL    3
#define VEOF     4
#define VEOL     5
#define VEOL2    6
#define VSWTC    7
#define VSTART   8
#define VSTOP    9
#define VSUSP    10
#define VDSUSP   11		/* SunOS POSIX nicety I do believe... */
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE  14
#define VLNEXT   15

/* User apps assume vmin/vtime is shared with eof/eol */
#define VMIN     VEOF
#define VTIME    VEOL

/* c_iflag bits */
#define IGNBRK	0x00000001
#define BRKINT	0x00000002
#define IGNPAR	0x00000004
#define PARMRK	0x00000008
#define INPCK	0x00000010
#define ISTRIP	0x00000020
#define INLCR	0x00000040
#define IGNCR	0x00000080
#define ICRNL	0x00000100
#define IUCLC	0x00000200
#define IXON	0x00000400
#define IXANY	0x00000800
#define IXOFF	0x00001000
#define IMAXBEL	0x00002000
#define IUTF8	0x00004000

/* c_oflag bits */
#define OPOST	0x00000001
#define OLCUC	0x00000002
#define ONLCR	0x00000004
#define OCRNL	0x00000008
#define ONOCR	0x00000010
#define ONLRET	0x00000020
#define OFILL	0x00000040
#define OFDEL	0x00000080
#if defined __USE_MISC || defined __USE_XOPEN
# define NLDLY	0x00000100
# define   NL0	0x00000000
# define   NL1	0x00000100
# define CRDLY	0x00000600
# define   CR0	0x00000000
# define   CR1	0x00000200
# define   CR2	0x00000400
# define   CR3	0x00000600
# define TABDLY	0x00001800
# define   TAB0	0x00000000
# define   TAB1	0x00000800
# define   TAB2	0x00001000
# define   TAB3	0x00001800
# define BSDLY	0x00002000
# define   BS0	0x00000000
# define   BS1	0x00002000
#define FFDLY	0x00008000
#define   FF0	0x00000000
#define   FF1	0x00008000
#endif
#define VTDLY	0x00004000
#define   VT0	0x00000000
#define   VT1	0x00004000
#define PAGEOUT 0x00010000	/* SUNOS specific */
#define WRAP    0x00020000	/* SUNOS specific */

#ifdef __USE_MISC
# define   XTABS	0x00001800
#endif

/* c_cflag bit meaning */
#ifdef __USE_MISC
# define CBAUD	0x0000100f
#endif
#define  B0	0x00000000	/* hang up */
#define  B50	0x00000001
#define  B75	0x00000002
#define  B110	0x00000003
#define  B134	0x00000004
#define  B150	0x00000005
#define  B200	0x00000006
#define  B300	0x00000007
#define  B600	0x00000008
#define  B1200	0x00000009
#define  B1800	0x0000000a
#define  B2400	0x0000000b
#define  B4800	0x0000000c
#define  B9600	0x0000000d
#define  B19200	0x0000000e
#define  B38400	0x0000000f
#ifdef __USE_MISC
# define EXTA    B19200
# define EXTB    B38400
#endif
#define  CSIZE  0x00000030
#define   CS5	0x00000000
#define   CS6	0x00000010
#define   CS7	0x00000020
#define   CS8	0x00000030
#define CSTOPB	0x00000040
#define CREAD	0x00000080
#define PARENB	0x00000100
#define PARODD	0x00000200
#define HUPCL	0x00000400
#define CLOCAL	0x00000800
#ifdef __USE_MISC
# define CBAUDEX 0x00001000
#endif
#define  B57600  0x00001001
#define  B115200 0x00001002
#define  B230400 0x00001003
#define  B460800 0x00001004
#define  B76800  0x00001005
#define  B153600 0x00001006
#define  B307200 0x00001007
#define  B614400 0x00001008
#define  B921600 0x00001009
#define  B500000 0x0000100a
#define  B576000 0x0000100b
#define B1000000 0x0000100c
#define B1152000 0x0000100d
#define B1500000 0x0000100e
#define B2000000 0x0000100f
#define __MAX_BAUD B2000000

#ifdef __USE_MISC
# define CIBAUD	 0x100f0000	/* input baud rate (not used) */
# define CMSPAR	 0x40000000	/* mark or space (stick) parity */
# define CRTSCTS 0x80000000	/* flow control */
#endif

/* c_lflag bits */
#define ISIG	0x00000001
#define ICANON	0x00000002
#if defined __USE_MISC || defined __USE_XOPEN
# define XCASE	0x00000004
#endif
#define ECHO	0x00000008
#define ECHOE	0x00000010
#define ECHOK	0x00000020
#define ECHONL	0x00000040
#define NOFLSH	0x00000080
#define TOSTOP	0x00000100
#ifdef __USE_MISC
# define ECHOCTL	0x00000200
# define ECHOPRT	0x00000400
# define ECHOKE		0x00000800
# define DEFECHO	0x00001000	/* SUNOS thing, what is it? */
# define FLUSHO		0x00002000
# define PENDIN		0x00004000
#endif
#define IEXTEN	0x00008000
#ifdef __USE_MISC
# define EXTPROC 0x00010000
#endif

/* modem lines */
#define TIOCM_LE	0x001
#define TIOCM_DTR	0x002
#define TIOCM_RTS	0x004
#define TIOCM_ST	0x008
#define TIOCM_SR	0x010
#define TIOCM_CTS	0x020
#define TIOCM_CAR	0x040
#define TIOCM_RNG	0x080
#define TIOCM_DSR	0x100
#define TIOCM_CD	TIOCM_CAR
#define TIOCM_RI	TIOCM_RNG

/* ioctl (fd, TIOCSERGETLSR, &result) where result may be as below */
#define TIOCSER_TEMT    0x01	/* Transmitter physically empty */


/* tcflow() and TCXONC use these */
#define	TCOOFF		0
#define	TCOON		1
#define	TCIOFF		2
#define	TCION		3

/* tcflush() and TCFLSH use these */
#define	TCIFLUSH	0
#define	TCOFLUSH	1
#define	TCIOFLUSH	2

/* tcsetattr uses these */
#define	TCSANOW		0
#define	TCSADRAIN	1
#define	TCSAFLUSH	2
