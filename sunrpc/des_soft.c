#if !defined(lint) && defined(SCCSIDS)
static char sccsid[] = "@(#)des_soft.c	2.2 88/08/10 4.0 RPCSRC; from 1.13 88/02/08 SMI";
#endif
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*
 * Table giving odd parity in the low bit for ASCII characters
 */
static char partab[128] =
{
  0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
  0x08, 0x08, 0x0b, 0x0b, 0x0d, 0x0d, 0x0e, 0x0e,
  0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
  0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f,
  0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
  0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f,
  0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
  0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e,
  0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
  0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f,
  0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
  0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e,
  0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
  0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e,
  0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
  0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f,
};

/*
 * Add odd parity to low bit of 8 byte key
 */
void
des_setparity (char *p)
{
  int i;

  for (i = 0; i < 8; i++)
    {
      *p = partab[*p & 0x7f];
      p++;
    }
}
