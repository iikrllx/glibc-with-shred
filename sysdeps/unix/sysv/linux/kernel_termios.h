/* The following corresponds to the values from the Linux 2.1.20 kernel.  */

#define KERNEL_NCCS 19

struct kernel_termios
  {
    tcflag_t c_iflag;		/* input mode flags */
    tcflag_t c_oflag;		/* output mode flags */
    tcflag_t c_cflag;		/* control mode flags */
    tcflag_t c_lflag;		/* local mode flags */
    cc_t c_line;		/* line discipline */
    cc_t c_cc[KERNEL_NCCS];	/* control characters */
  };
