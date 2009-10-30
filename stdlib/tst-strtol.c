/* My bet is this was written by Chris Torek.
   I reformatted and ansidecl-ized it, and tweaked it a little.  */

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct ltest
  {
    const char *str;		/* Convert this.  */
    unsigned long int expect;	/* To get this.  */
    int base;			/* Use this base.  */
    char left;			/* With this left over.  */
    int err;			/* And this in errno.  */
  };
static const struct ltest tests[] =
  {
  /* First, signed numbers:  */
  /* simple... */
  {"123", 123, 0, 0, 0},
  {"+123", 123, 0, 0, 0},
  {"  123", 123, 0, 0, 0},
  {" 123 ", 123, 0, ' ', 0},
  {"   -17", -17, 0, 0, 0},

  /* implicit base... */
  {"0123", 0123, 0, 0, 0},
  {"0123a", 0123, 0, 'a', 0},
  {"01239", 0123, 0, '9', 0},
  {"0x123", 0x123, 0, 0, 0},
  {"-0x123", -0x123, 0, 0, 0},
  {"0x0xc", 0, 0, 'x', 0},
  {" +0x123fg", 0x123f, 0, 'g', 0},

  /* explicit base... */
  {"123", 0x123, 16, 0, 0},
  {"0x123", 0x123, 16, 0, 0},
  {"123", 0123, 8, 0, 0},
  {"0123", 0123, 8, 0, 0},
  {"0123", 123, 10, 0, 0},
  {"0x123", 0, 10, 'x', 0},

  /* case insensitivity... */
  {"abcd", 0xabcd, 16, 0, 0},
  {"AbCd", 0xabcd, 16, 0, 0},
  {"0xABCD", 0xabcd, 16, 0, 0},
  {"0Xabcd", 0xabcd, 16, 0, 0},

  /* odd bases... */
  {"0xyz", 33 * 35 + 34, 35, 'z', 0},
  {"yz!", 34 * 36 + 35, 36, '!', 0},
  {"-yz", -(34*36 + 35), 36, 0, 0},
  {"GhI4", ((16*20 + 17)*20 + 18)*20 + 4, 20, 0, 0},

  /* extremes... */
#if LONG_MAX == 0x7fffffff
  {"2147483647", 2147483647, 0, 0, 0},
  {"2147483648", 2147483647, 0, 0, ERANGE},
  {"214748364888", 2147483647, 0, 0, ERANGE},
  {"2147483650", 2147483647, 0, 0, ERANGE},
  {"-2147483648", 0x80000000, 0, 0, 0},
  {"-2147483649", 0x80000000, 0, 0, ERANGE},
  {"0x1122334455z", 2147483647, 16, 'z', ERANGE},

  {"1111111111111111111111111111111", 2147483647, 2, 0, 0},
  {"10000000000000000000000000000000", 2147483647, 2, 0, ERANGE},
  {"12112122212110202101", 2147483647, 3, 0, 0},
  {"12112122212110202102", 2147483647, 3, 0, ERANGE},
  {"1333333333333333", 2147483647, 4, 0, 0},
  {"2000000000000000", 2147483647, 4, 0, ERANGE},
  {"13344223434042", 2147483647, 5, 0, 0},
  {"13344223434043", 2147483647, 5, 0, ERANGE},
  {"553032005531", 2147483647, 6, 0, 0},
  {"553032005532", 2147483647, 6, 0, ERANGE},
  {"104134211161", 2147483647, 7, 0, 0},
  {"104134211162", 2147483647, 7, 0, ERANGE},
  {"17777777777", 2147483647, 8, 0, 0},
  {"20000000000", 2147483647, 8, 0, ERANGE},
  {"5478773671", 2147483647, 9, 0, 0},
  {"5478773672", 2147483647, 9, 0, ERANGE},
  {"2147483647", 2147483647, 10, 0, 0},
  {"2147483648", 2147483647, 10, 0, ERANGE},
  {"a02220281", 2147483647, 11, 0, 0},
  {"a02220282", 2147483647, 11, 0, ERANGE},
  {"4bb2308a7", 2147483647, 12, 0, 0},
  {"4bb2308a8", 2147483647, 12, 0, ERANGE},
  {"282ba4aaa", 2147483647, 13, 0, 0},
  {"282ba4aab", 2147483647, 13, 0, ERANGE},
  {"1652ca931", 2147483647, 14, 0, 0},
  {"1652ca932", 2147483647, 14, 0, ERANGE},
  {"c87e66b7", 2147483647, 15, 0, 0},
  {"c87e66b8", 2147483647, 15, 0, ERANGE},
  {"7fffffff", 2147483647, 16, 0, 0},
  {"80000000", 2147483647, 16, 0, ERANGE},
  {"53g7f548", 2147483647, 17, 0, 0},
  {"53g7f549", 2147483647, 17, 0, ERANGE},
  {"3928g3h1", 2147483647, 18, 0, 0},
  {"3928g3h2", 2147483647, 18, 0, ERANGE},
  {"27c57h32", 2147483647, 19, 0, 0},
  {"27c57h33", 2147483647, 19, 0, ERANGE},
  {"1db1f927", 2147483647, 20, 0, 0},
  {"1db1f928", 2147483647, 20, 0, ERANGE},
  {"140h2d91", 2147483647, 21, 0, 0},
  {"140h2d92", 2147483647, 21, 0, ERANGE},
  {"ikf5bf1", 2147483647, 22, 0, 0},
  {"ikf5bf2", 2147483647, 22, 0, ERANGE},
  {"ebelf95", 2147483647, 23, 0, 0},
  {"ebelf96", 2147483647, 23, 0, ERANGE},
  {"b5gge57", 2147483647, 24, 0, 0},
  {"b5gge58", 2147483647, 24, 0, ERANGE},
  {"8jmdnkm", 2147483647, 25, 0, 0},
  {"8jmdnkn", 2147483647, 25, 0, ERANGE},
  {"6oj8ion", 2147483647, 26, 0, 0},
  {"6oj8ioo", 2147483647, 26, 0, ERANGE},
  {"5ehncka", 2147483647, 27, 0, 0},
  {"5ehnckb", 2147483647, 27, 0, ERANGE},
  {"4clm98f", 2147483647, 28, 0, 0},
  {"4clm98g", 2147483647, 28, 0, ERANGE},
  {"3hk7987", 2147483647, 29, 0, 0},
  {"3hk7988", 2147483647, 29, 0, ERANGE},
  {"2sb6cs7", 2147483647, 30, 0, 0},
  {"2sb6cs8", 2147483647, 30, 0, ERANGE},
  {"2d09uc1", 2147483647, 31, 0, 0},
  {"2d09uc2", 2147483647, 31, 0, ERANGE},
  {"1vvvvvv", 2147483647, 32, 0, 0},
  {"2000000", 2147483647, 32, 0, ERANGE},
  {"1lsqtl1", 2147483647, 33, 0, 0},
  {"1lsqtl2", 2147483647, 33, 0, ERANGE},
  {"1d8xqrp", 2147483647, 34, 0, 0},
  {"1d8xqrq", 2147483647, 34, 0, ERANGE},
  {"15v22um", 2147483647, 35, 0, 0},
  {"15v22un", 2147483647, 35, 0, ERANGE},
  {"zik0zj", 2147483647, 36, 0, 0},
  {"zik0zk", 2147483647, 36, 0, ERANGE},

  {"-10000000000000000000000000000000", -2147483648, 2, 0, 0},
  {"-10000000000000000000000000000001", -2147483648, 2, 0, ERANGE},
  {"-12112122212110202102", -2147483648, 3, 0, 0},
  {"-12112122212110202110", -2147483648, 3, 0, ERANGE},
  {"-2000000000000000", -2147483648, 4, 0, 0},
  {"-2000000000000001", -2147483648, 4, 0, ERANGE},
  {"-13344223434043", -2147483648, 5, 0, 0},
  {"-13344223434044", -2147483648, 5, 0, ERANGE},
  {"-553032005532", -2147483648, 6, 0, 0},
  {"-553032005533", -2147483648, 6, 0, ERANGE},
  {"-104134211162", -2147483648, 7, 0, 0},
  {"-104134211163", -2147483648, 7, 0, ERANGE},
  {"-20000000000", -2147483648, 8, 0, },
  {"-20000000001", -2147483648, 8, 0, ERANGE},
  {"-5478773672", -2147483648, 9, 0, 0},
  {"-5478773673", -2147483648, 9, 0, ERANGE},
  {"-2147483648", -2147483648, 10, 0, 0},
  {"-2147483649", -2147483648, 10, 0, ERANGE},
  {"-a02220282", -2147483648, 11, 0, 0},
  {"-a02220283", -2147483648, 11, 0, ERANGE},
  {"-4bb2308a8", -2147483648, 12, 0, 0},
  {"-4bb2308a9", -2147483648, 12, 0, ERANGE},
  {"-282ba4aab", -2147483648, 13, 0, 0},
  {"-282ba4aac", -2147483648, 13, 0, ERANGE},
  {"-1652ca932", -2147483648, 14, 0, 0},
  {"-1652ca933", -2147483648, 14, 0, ERANGE},
  {"-c87e66b8", -2147483648, 15, 0, 0},
  {"-c87e66b9", -2147483648, 15, 0, ERANGE},
  {"-80000000", -2147483648, 16, 0, 0},
  {"-80000001", -2147483648, 16, 0, ERANGE},
  {"-53g7f549", -2147483648, 17, 0, 0},
  {"-53g7f54a", -2147483648, 17, 0, ERANGE},
  {"-3928g3h2", -2147483648, 18, 0, 0},
  {"-3928g3h3", -2147483648, 18, 0, ERANGE},
  {"-27c57h33", -2147483648, 19, 0, 0},
  {"-27c57h34", -2147483648, 19, 0, ERANGE},
  {"-1db1f928", -2147483648, 20, 0, 0},
  {"-1db1f929", -2147483648, 20, 0, ERANGE},
  {"-140h2d92", -2147483648, 21, 0, 0},
  {"-140h2d93", -2147483648, 21, 0, ERANGE},
  {"-ikf5bf2", -2147483648, 22, 0, 0},
  {"-ikf5bf3", -2147483648, 22, 0, ERANGE},
  {"-ebelf96", -2147483648, 23, 0, 0},
  {"-ebelf97", -2147483648, 23, 0, ERANGE},
  {"-b5gge58", -2147483648, 24, 0, 0},
  {"-b5gge59", -2147483648, 24, 0, ERANGE},
  {"-8jmdnkn", -2147483648, 25, 0, 0},
  {"-8jmdnko", -2147483648, 25, 0, ERANGE},
  {"-6oj8ioo", -2147483648, 26, 0, 0},
  {"-6oj8iop", -2147483648, 26, 0, ERANGE},
  {"-5ehnckb", -2147483648, 27, 0, 0},
  {"-5ehnckc", -2147483648, 27, 0, ERANGE},
  {"-4clm98g", -2147483648, 28, 0, 0},
  {"-4clm98h", -2147483648, 28, 0, ERANGE},
  {"-3hk7988", -2147483648, 29, 0, 0},
  {"-3hk7989", -2147483648, 29, 0, ERANGE},
  {"-2sb6cs8", -2147483648, 30, 0, 0},
  {"-2sb6cs9", -2147483648, 30, 0, ERANGE},
  {"-2d09uc2", -2147483648, 31, 0, 0},
  {"-2d09uc3", -2147483648, 31, 0, ERANGE},
  {"-2000000", -2147483648, 32, 0, 0},
  {"-2000001", -2147483648, 32, 0, ERANGE},
  {"-1lsqtl2", -2147483648, 33, 0, 0},
  {"-1lsqtl3", -2147483648, 33, 0, ERANGE},
  {"-1d8xqrq", -2147483648, 34, 0, 0},
  {"-1d8xqrr", -2147483648, 34, 0, ERANGE},
  {"-15v22un", -2147483648, 35, 0, 0},
  {"-15v22uo", -2147483648, 35, 0, ERANGE},
  {"-zik0zk", -2147483648, 36, 0, 0},
  {"-zik0zl", -2147483648, 36, 0, ERANGE},
#else
  {"9223372036854775807", 9223372036854775807, 0, 0, 0},
  {"9223372036854775808", 9223372036854775807, 0, 0, ERANGE},
  {"922337203685477580777", 9223372036854775807, 0, 0, ERANGE},
  {"9223372036854775810", 9223372036854775807, 0, 0, ERANGE},
  {"-2147483648", -2147483648, 0, 0, 0},
  {"-9223372036854775808", 0x8000000000000000, 0, 0, 0},
  {"-9223372036854775809", 0x8000000000000000, 0, 0, ERANGE},
  {"0x112233445566778899z", 9223372036854775807, 16, 'z', ERANGE},
  {"0xFFFFFFFFFFFF00FF" , 9223372036854775807, 0, 0, ERANGE},

  {"111111111111111111111111111111111111111111111111111111111111111",
   9223372036854775807, 2, 0, 0},
  {"1000000000000000000000000000000000000000000000000000000000000000",
   9223372036854775807, 2, 0, ERANGE},
  {"2021110011022210012102010021220101220221",
   9223372036854775807, 3, 0, 0},
  {"2021110011022210012102010021220101220222",
   9223372036854775807, 3, 0, ERANGE},
  {"13333333333333333333333333333333", 9223372036854775807, 4, 0, 0},
  {"20000000000000000000000000000000", 9223372036854775807, 4, 0, ERANGE},
  {"1104332401304422434310311212", 9223372036854775807, 5, 0, 0},
  {"1104332401304422434310311213", 9223372036854775807, 5, 0, ERANGE},
  {"1540241003031030222122211", 9223372036854775807, 6, 0, 0},
  {"1540241003031030222122212", 9223372036854775807, 6, 0, ERANGE},
  {"22341010611245052052300", 9223372036854775807, 7, 0, 0},
  {"22341010611245052052301", 9223372036854775807, 7, 0, ERANGE},
  {"777777777777777777777", 9223372036854775807, 8, 0, 0},
  {"1000000000000000000000", 9223372036854775807, 8, 0, ERANGE},
  {"67404283172107811827", 9223372036854775807, 9, 0, 0},
  {"67404283172107811828", 9223372036854775807, 9, 0, ERANGE},
  {"9223372036854775807", 9223372036854775807, 10, 0, 0},
  {"9223372036854775808", 9223372036854775807, 10, 0, ERANGE},
  {"1728002635214590697", 9223372036854775807, 11, 0, 0},
  {"1728002635214590698", 9223372036854775807, 11, 0, ERANGE},
  {"41a792678515120367", 9223372036854775807, 12, 0, 0},
  {"41a792678515120368", 9223372036854775807, 12, 0, ERANGE},
  {"10b269549075433c37", 9223372036854775807, 13, 0, 0},
  {"10b269549075433c38", 9223372036854775807, 13, 0, ERANGE},
  {"4340724c6c71dc7a7", 9223372036854775807, 14, 0, 0},
  {"4340724c6c71dc7a8", 9223372036854775807, 14, 0, ERANGE},
  {"160e2ad3246366807", 9223372036854775807, 15, 0, 0},
  {"160e2ad3246366808", 9223372036854775807, 15, 0, ERANGE},
  {"7fffffffffffffff", 9223372036854775807, 16, 0, 0},
  {"8000000000000000", 9223372036854775807, 16, 0, ERANGE},
  {"33d3d8307b214008", 9223372036854775807, 17, 0, 0},
  {"33d3d8307b214009", 9223372036854775807, 17, 0, ERANGE},
  {"16agh595df825fa7", 9223372036854775807, 18, 0, 0},
  {"16agh595df825fa8", 9223372036854775807, 18, 0, ERANGE},
  {"ba643dci0ffeehh", 9223372036854775807, 19, 0, 0},
  {"ba643dci0ffeehi", 9223372036854775807, 19, 0, ERANGE},
  {"5cbfjia3fh26ja7", 9223372036854775807, 20, 0, 0},
  {"5cbfjia3fh26ja8", 9223372036854775807, 20, 0, ERANGE},
  {"2heiciiie82dh97", 9223372036854775807, 21, 0, 0},
  {"2heiciiie82dh98", 9223372036854775807, 21, 0, ERANGE},
  {"1adaibb21dckfa7", 9223372036854775807, 22, 0, 0},
  {"1adaibb21dckfa8", 9223372036854775807, 22, 0, ERANGE},
  {"i6k448cf4192c2", 9223372036854775807, 23, 0, 0},
  {"i6k448cf4192c3", 9223372036854775807, 23, 0, ERANGE},
  {"acd772jnc9l0l7", 9223372036854775807, 24, 0, 0},
  {"acd772jnc9l0l8", 9223372036854775807, 24, 0, ERANGE},
  {"64ie1focnn5g77", 9223372036854775807, 25, 0, 0},
  {"64ie1focnn5g78", 9223372036854775807, 25, 0, ERANGE},
  {"3igoecjbmca687", 9223372036854775807, 26, 0, 0},
  {"3igoecjbmca688", 9223372036854775807, 26, 0, ERANGE},
  {"27c48l5b37oaop", 9223372036854775807, 27, 0, 0},
  {"27c48l5b37oaoq", 9223372036854775807, 27, 0, ERANGE},
  {"1bk39f3ah3dmq7", 9223372036854775807, 28, 0, 0},
  {"1bk39f3ah3dmq8", 9223372036854775807, 28, 0, ERANGE},
  {"q1se8f0m04isb", 9223372036854775807, 29, 0, 0},
  {"q1se8f0m04isc", 9223372036854775807, 29, 0, ERANGE},
  {"hajppbc1fc207", 9223372036854775807, 30, 0, 0},
  {"hajppbc1fc208", 9223372036854775807, 30, 0, ERANGE},
  {"bm03i95hia437", 9223372036854775807, 31, 0, 0},
  {"bm03i95hia438", 9223372036854775807, 31, 0, ERANGE},
  {"7vvvvvvvvvvvv", 9223372036854775807, 32, 0, 0},
  {"8000000000000", 9223372036854775807, 32, 0, ERANGE},
  {"5hg4ck9jd4u37", 9223372036854775807, 33, 0, 0},
  {"5hg4ck9jd4u38", 9223372036854775807, 33, 0, ERANGE},
  {"3tdtk1v8j6tpp", 9223372036854775807, 34, 0, 0},
  {"3tdtk1v8j6tpq", 9223372036854775807, 34, 0, ERANGE},
  {"2pijmikexrxp7", 9223372036854775807, 35, 0, 0},
  {"2pijmikexrxp8", 9223372036854775807, 35, 0, ERANGE},
  {"1y2p0ij32e8e7", 9223372036854775807, 36, 0, 0},
  {"1y2p0ij32e8e8", 9223372036854775807, 36, 0, ERANGE},

  {"-1000000000000000000000000000000000000000000000000000000000000000",
   -9223372036854775808ull, 2, 0, 0},
  {"-1000000000000000000000000000000000000000000000000000000000000001",
   -9223372036854775808ull, 2, 0, ERANGE},
  {"-2021110011022210012102010021220101220222",
   -9223372036854775808ull, 3, 0, 0},
  {"-2021110011022210012102010021220101221000",
   -9223372036854775808ull, 3, 0, ERANGE},
  {"-20000000000000000000000000000000", -9223372036854775808ull, 4, 0, 0},
  {"-20000000000000000000000000000001", -9223372036854775808ull, 4, 0, ERANGE},
  {"-1104332401304422434310311213", -9223372036854775808ull, 5, 0, 0},
  {"-1104332401304422434310311214", -9223372036854775808ull, 5, 0, ERANGE},
  {"-1540241003031030222122212", -9223372036854775808ull, 6, 0, 0},
  {"-1540241003031030222122213", -9223372036854775808ull, 6, 0, ERANGE},
  {"-22341010611245052052301", -9223372036854775808ull, 7, 0, 0},
  {"-22341010611245052052302", -9223372036854775808ull, 7, 0, ERANGE},
  {"-1000000000000000000000", -9223372036854775808ull, 8, 0, 0},
  {"-1000000000000000000001", -9223372036854775808ull, 8, 0, ERANGE},
  {"-67404283172107811828", -9223372036854775808ull, 9, 0, 0},
  {"-67404283172107811830", -9223372036854775808ull, 9, 0, ERANGE},
  {"-9223372036854775808", -9223372036854775808ull, 10, 0, 0},
  {"-9223372036854775809", -9223372036854775808ull, 10, 0, ERANGE},
  {"-1728002635214590698", -9223372036854775808ull, 11, 0, 0},
  {"-1728002635214590699", -9223372036854775808ull, 11, 0, ERANGE},
  {"-41a792678515120368", -9223372036854775808ull, 12, 0, 0},
  {"-41a792678515120369", -9223372036854775808ull, 12, 0, ERANGE},
  {"-10b269549075433c38", -9223372036854775808ull, 13, 0, 0},
  {"-10b269549075433c39", -9223372036854775808ull, 13, 0, ERANGE},
  {"-4340724c6c71dc7a8", -9223372036854775808ull, 14, 0, 0},
  {"-4340724c6c71dc7a9", -9223372036854775808ull, 14, 0, ERANGE},
  {"-160e2ad3246366808", -9223372036854775808ull, 15, 0, 0},
  {"-160e2ad3246366809", -9223372036854775808ull, 15, 0, ERANGE},
  {"-8000000000000000", -9223372036854775808ull, 16, 0, 0},
  {"-8000000000000001", -9223372036854775808ull, 16, 0, ERANGE},
  {"-33d3d8307b214009", -9223372036854775808ull, 17, 0, 0},
  {"-33d3d8307b21400a", -9223372036854775808ull, 17, 0, ERANGE},
  {"-16agh595df825fa8", -9223372036854775808ull, 18, 0, 0},
  {"-16agh595df825fa9", -9223372036854775808ull, 18, 0, ERANGE},
  {"-ba643dci0ffeehi", -9223372036854775808ull, 19, 0, 0},
  {"-ba643dci0ffeei0", -9223372036854775808ull, 19, 0, ERANGE},
  {"-5cbfjia3fh26ja8", -9223372036854775808ull, 20, 0, 0},
  {"-5cbfjia3fh26ja9", -9223372036854775808ull, 20, 0, ERANGE},
  {"-2heiciiie82dh98", -9223372036854775808ull, 21, 0, 0},
  {"-2heiciiie82dh99", -9223372036854775808ull, 21, 0, ERANGE},
  {"-1adaibb21dckfa8", -9223372036854775808ull, 22, 0, 0},
  {"-1adaibb21dckfa9", -9223372036854775808ull, 22, 0, ERANGE},
  {"-i6k448cf4192c3", -9223372036854775808ull, 23, 0, 0},
  {"-i6k448cf4192c4", -9223372036854775808ull, 23, 0, ERANGE},
  {"-acd772jnc9l0l8", -9223372036854775808ull, 24, 0, 0},
  {"-acd772jnc9l0l9", -9223372036854775808ull, 24, 0, ERANGE},
  {"-64ie1focnn5g78", -9223372036854775808ull, 25, 0, 0},
  {"-64ie1focnn5g79", -9223372036854775808ull, 25, 0, ERANGE},
  {"-3igoecjbmca688", -9223372036854775808ull, 26, 0, 0},
  {"-3igoecjbmca689", -9223372036854775808ull, 26, 0, ERANGE},
  {"-27c48l5b37oaoq", -9223372036854775808ull, 27, 0, 0},
  {"-27c48l5b37oap0", -9223372036854775808ull, 27, 0, ERANGE},
  {"-1bk39f3ah3dmq8", -9223372036854775808ull, 28, 0, 0},
  {"-1bk39f3ah3dmq9", -9223372036854775808ull, 28, 0, ERANGE},
  {"-q1se8f0m04isc", -9223372036854775808ull, 29, 0, 0},
  {"-q1se8f0m04isd", -9223372036854775808ull, 29, 0, ERANGE},
  {"-hajppbc1fc208", -9223372036854775808ull, 30, 0, 0},
  {"-hajppbc1fc209", -9223372036854775808ull, 30, 0, ERANGE},
  {"-bm03i95hia438", -9223372036854775808ull, 31, 0, 0},
  {"-bm03i95hia439", -9223372036854775808ull, 31, 0, ERANGE},
  {"-8000000000000", -9223372036854775808ull, 32, 0, 0},
  {"-8000000000001", -9223372036854775808ull, 32, 0, ERANGE},
  {"-5hg4ck9jd4u38", -9223372036854775808ull, 33, 0, 0},
  {"-5hg4ck9jd4u39", -9223372036854775808ull, 33, 0, ERANGE},
  {"-3tdtk1v8j6tpq", -9223372036854775808ull, 34, 0, 0},
  {"-3tdtk1v8j6tpr", -9223372036854775808ull, 34, 0, ERANGE},
  {"-2pijmikexrxp8", -9223372036854775808ull, 35, 0, 0},
  {"-2pijmikexrxp9", -9223372036854775808ull, 35, 0, ERANGE},
  {"-1y2p0ij32e8e8", -9223372036854775808ull, 36, 0, 0},
  {"-1y2p0ij32e8e9", -9223372036854775808ull, 36, 0, ERANGE},
#endif
  {NULL, 0, 0, 0, 0},

  /* Then unsigned.  */
  {"  0", 0, 0, 0, 0},
  {"0xffffffffg", 0xffffffff, 0, 'g', 0},
#if LONG_MAX == 0x7fffffff
  {"-0xfedcba98", 0x01234568, 0, 0, 0},
  {"0xf1f2f3f4f5", 0xffffffff, 0, 0, ERANGE},
  {"-0x123456789", 0xffffffff, 0, 0, ERANGE},

  {"11111111111111111111111111111111", 0xffffffff, 2, 0, 0},
  {"100000000000000000000000000000000", 0xffffffff, 2, 0, ERANGE},
  {"102002022201221111210", 0xffffffff, 3, 0, 0},
  {"102002022201221111211", 0xffffffff, 3, 0, ERANGE},
  {"3333333333333333", 0xffffffff, 4, 0, 0},
  {"10000000000000000", 0xffffffff, 4, 0, ERANGE},
  {"32244002423140", 0xffffffff, 5, 0, 0},
  {"32244002423141", 0xffffffff, 5, 0, ERANGE},
  {"1550104015503", 0xffffffff, 6, 0, 0},
  {"1550104015504", 0xffffffff, 6, 0, ERANGE},
  {"211301422353", 0xffffffff, 7, 0, 0},
  {"211301422354", 0xffffffff, 7, 0, ERANGE},
  {"37777777777", 0xffffffff, 8, 0, 0},
  {"40000000000", 0xffffffff, 8, 0, ERANGE},
  {"12068657453", 0xffffffff, 9, 0, 0},
  {"12068657454", 0xffffffff, 9, 0, ERANGE},
  {"4294967295", 0xffffffff, 10, 0, 0},
  {"4294967296", 0xffffffff, 10, 0, ERANGE},
  {"1904440553", 0xffffffff, 11, 0, 0},
  {"1904440554", 0xffffffff, 11, 0, ERANGE},
  {"9ba461593", 0xffffffff, 12, 0, 0},
  {"9ba461594", 0xffffffff, 12, 0, ERANGE},
  {"535a79888", 0xffffffff, 13, 0, 0},
  {"535a79889", 0xffffffff, 13, 0, ERANGE},
  {"2ca5b7463", 0xffffffff, 14, 0, 0},
  {"2ca5b7464", 0xffffffff, 14, 0, ERANGE},
  {"1a20dcd80", 0xffffffff, 15, 0, 0},
  {"1a20dcd81", 0xffffffff, 15, 0, ERANGE},
  {"ffffffff", 0xffffffff, 16, 0, 0},
  {"100000000", 0xffffffff, 16, 0, ERANGE},
  {"a7ffda90", 0xffffffff, 17, 0, 0},
  {"a7ffda91", 0xffffffff, 17, 0, ERANGE},
  {"704he7g3", 0xffffffff, 18, 0, 0},
  {"704he7g4", 0xffffffff, 18, 0, ERANGE},
  {"4f5aff65", 0xffffffff, 19, 0, 0},
  {"4f5aff66", 0xffffffff, 19, 0, ERANGE},
  {"3723ai4f", 0xffffffff, 20, 0, 0},
  {"3723ai4g", 0xffffffff, 20, 0, ERANGE},
  {"281d55i3", 0xffffffff, 21, 0, 0},
  {"281d55i4", 0xffffffff, 21, 0, ERANGE},
  {"1fj8b183", 0xffffffff, 22, 0, 0},
  {"1fj8b184", 0xffffffff, 22, 0, ERANGE},
  {"1606k7ib", 0xffffffff, 23, 0, 0},
  {"1606k7ic", 0xffffffff, 23, 0, ERANGE},
  {"mb994af", 0xffffffff, 24, 0, 0},
  {"mb994ag", 0xffffffff, 24, 0, ERANGE},
  {"hek2mgk", 0xffffffff, 25, 0, 0},
  {"hek2mgl", 0xffffffff, 25, 0, ERANGE},
  {"dnchbnl", 0xffffffff, 26, 0, 0},
  {"dnchbnm", 0xffffffff, 26, 0, ERANGE},
  {"b28jpdl", 0xffffffff, 27, 0, 0},
  {"b28jpdm", 0xffffffff, 27, 0, ERANGE},
  {"8pfgih3", 0xffffffff, 28, 0, 0},
  {"8pfgih4", 0xffffffff, 28, 0, ERANGE},
  {"76beigf", 0xffffffff, 29, 0, 0},
  {"76beigg", 0xffffffff, 29, 0, ERANGE},
  {"5qmcpqf", 0xffffffff, 30, 0, 0},
  {"5qmcpqg", 0xffffffff, 30, 0, ERANGE},
  {"4q0jto3", 0xffffffff, 31, 0, 0},
  {"4q0jto4", 0xffffffff, 31, 0, ERANGE},
  {"3vvvvvv", 0xffffffff, 32, 0, 0},
  {"4000000", 0xffffffff, 32, 0, ERANGE},
  {"3aokq93", 0xffffffff, 33, 0, 0},
  {"3aokq94", 0xffffffff, 33, 0, ERANGE},
  {"2qhxjlh", 0xffffffff, 34, 0, 0},
  {"2qhxjli", 0xffffffff, 34, 0, ERANGE},
  {"2br45qa", 0xffffffff, 35, 0, 0},
  {"2br45qb", 0xffffffff, 35, 0, ERANGE},
  {"1z141z3", 0xffffffff, 36, 0, 0},
  {"1z141z4", 0xffffffff, 36, 0, ERANGE},
#else
  {"0xffffffffffffffffg", 0xffffffffffffffff, 0, 'g', 0},
  {"-0xfedcba987654321", 0xf0123456789abcdf, 0, 0, 0},
  {"0xf1f2f3f4f5f6f7f8f9", 0xffffffffffffffff, 0, 0, ERANGE},
  {"-0x123456789abcdef01", 0xffffffffffffffff, 0, 0, ERANGE},

  {"1111111111111111111111111111111111111111111111111111111111111111",
   0xffffffffffffffff, 2, 0, 0},
  {"10000000000000000000000000000000000000000000000000000000000000000",
   0xffffffffffffffff, 2, 0, ERANGE},
  {"11112220022122120101211020120210210211220",
   0xffffffffffffffff, 3, 0, 0},
  {"11112220022122120101211020120210210211221",
   0xffffffffffffffff, 3, 0, ERANGE},
  {"33333333333333333333333333333333", 0xffffffffffffffff, 4, 0, 0},
  {"100000000000000000000000000000000", 0xffffffffffffffff, 4, 0, ERANGE},
  {"2214220303114400424121122430", 0xffffffffffffffff, 5, 0, 0},
  {"2214220303114400424121122431", 0xffffffffffffffff, 5, 0, ERANGE},
  {"3520522010102100444244423", 0xffffffffffffffff, 6, 0, 0},
  {"3520522010102100444244424", 0xffffffffffffffff, 6, 0, ERANGE},
  {"45012021522523134134601", 0xffffffffffffffff, 7, 0, 0},
  {"45012021522523134134602", 0xffffffffffffffff, 7, 0, ERANGE},
  {"1777777777777777777777", 0xffffffffffffffff, 8, 0, 0},
  {"2000000000000000000000", 0xffffffffffffffff, 8, 0, ERANGE},
  {"145808576354216723756", 0xffffffffffffffff, 9, 0, 0},
  {"145808576354216723757", 0xffffffffffffffff, 9, 0, ERANGE},
  {"18446744073709551615", 0xffffffffffffffff, 10, 0, 0},
  {"18446744073709551616", 0xffffffffffffffff, 10, 0, ERANGE},
  {"335500516a429071284", 0xffffffffffffffff, 11, 0, 0},
  {"335500516a429071285", 0xffffffffffffffff, 11, 0, ERANGE},
  {"839365134a2a240713", 0xffffffffffffffff, 12, 0, 0},
  {"839365134a2a240714", 0xffffffffffffffff, 12, 0, ERANGE},
  {"219505a9511a867b72", 0xffffffffffffffff, 13, 0, 0},
  {"219505a9511a867b73", 0xffffffffffffffff, 13, 0, ERANGE},
  {"8681049adb03db171", 0xffffffffffffffff, 14, 0, 0},
  {"8681049adb03db172", 0xffffffffffffffff, 14, 0, ERANGE},
  {"2c1d56b648c6cd110", 0xffffffffffffffff, 15, 0, 0},
  {"2c1d56b648c6cd111", 0xffffffffffffffff, 15, 0, ERANGE},
  {"ffffffffffffffff", 0xffffffffffffffff, 16, 0, 0},
  {"10000000000000000", 0xffffffffffffffff, 16, 0, ERANGE},
  {"67979g60f5428010", 0xffffffffffffffff, 17, 0, 0},
  {"67979g60f5428011", 0xffffffffffffffff, 17, 0, ERANGE},
  {"2d3fgb0b9cg4bd2f", 0xffffffffffffffff, 18, 0, 0},
  {"2d3fgb0b9cg4bd2g", 0xffffffffffffffff, 18, 0, ERANGE},
  {"141c8786h1ccaagg", 0xffffffffffffffff, 19, 0, 0},
  {"141c8786h1ccaagh", 0xffffffffffffffff, 19, 0, ERANGE},
  {"b53bjh07be4dj0f", 0xffffffffffffffff, 20, 0, 0},
  {"b53bjh07be4dj0g", 0xffffffffffffffff, 20, 0, ERANGE},
  {"5e8g4ggg7g56dif", 0xffffffffffffffff, 21, 0, 0},
  {"5e8g4ggg7g56dig", 0xffffffffffffffff, 21, 0, ERANGE},
  {"2l4lf104353j8kf", 0xffffffffffffffff, 22, 0, 0},
  {"2l4lf104353j8kg", 0xffffffffffffffff, 22, 0, ERANGE},
  {"1ddh88h2782i515", 0xffffffffffffffff, 23, 0, 0},
  {"1ddh88h2782i516", 0xffffffffffffffff, 23, 0, ERANGE},
  {"l12ee5fn0ji1if", 0xffffffffffffffff, 24, 0, 0},
  {"l12ee5fn0ji1ig", 0xffffffffffffffff, 24, 0, ERANGE},
  {"c9c336o0mlb7ef", 0xffffffffffffffff, 25, 0, 0},
  {"c9c336o0mlb7eg", 0xffffffffffffffff, 25, 0, ERANGE},
  {"7b7n2pcniokcgf", 0xffffffffffffffff, 26, 0, 0},
  {"7b7n2pcniokcgg", 0xffffffffffffffff, 26, 0, ERANGE},
  {"4eo8hfam6fllmo", 0xffffffffffffffff, 27, 0, 0},
  {"4eo8hfam6fllmp", 0xffffffffffffffff, 27, 0, ERANGE},
  {"2nc6j26l66rhof", 0xffffffffffffffff, 28, 0, 0},
  {"2nc6j26l66rhog", 0xffffffffffffffff, 28, 0, ERANGE},
  {"1n3rsh11f098rn", 0xffffffffffffffff, 29, 0, 0},
  {"1n3rsh11f098ro", 0xffffffffffffffff, 29, 0, ERANGE},
  {"14l9lkmo30o40f", 0xffffffffffffffff, 30, 0, 0},
  {"14l9lkmo30o40g", 0xffffffffffffffff, 30, 0, ERANGE},
  {"nd075ib45k86f", 0xffffffffffffffff, 31, 0, 0},
  {"nd075ib45k86g", 0xffffffffffffffff, 31, 0, ERANGE},
  {"fvvvvvvvvvvvv", 0xffffffffffffffff, 32, 0, 0},
  {"g000000000000", 0xffffffffffffffff, 32, 0, ERANGE},
  {"b1w8p7j5q9r6f", 0xffffffffffffffff, 33, 0, 0},
  {"b1w8p7j5q9r6g", 0xffffffffffffffff, 33, 0, ERANGE},
  {"7orp63sh4dphh", 0xffffffffffffffff, 34, 0, 0},
  {"7orp63sh4dphi", 0xffffffffffffffff, 34, 0, ERANGE},
  {"5g24a25twkwff", 0xffffffffffffffff, 35, 0, 0},
  {"5g24a25twkwfg", 0xffffffffffffffff, 35, 0, ERANGE},
  {"3w5e11264sgsf", 0xffffffffffffffff, 36, 0, 0},
  {"3w5e11264sgsg", 0xffffffffffffffff, 36, 0, ERANGE},
#endif
  {NULL, 0, 0, 0, 0},
  };

/* Prototypes for local functions.  */
static void expand (char *dst, int c);

int
main (void)
{
  register const struct ltest *lt;
  char *ep;
  int status = 0;
  int save_errno;

  for (lt = tests; lt->str != NULL; ++lt)
    {
      register long int l;

      errno = 0;
      l = strtol (lt->str, &ep, lt->base);
      save_errno = errno;
      printf ("strtol(\"%s\", , %d) test %u",
	      lt->str, lt->base, (unsigned int) (lt - tests));
      if (l == (long int) lt->expect && *ep == lt->left
	  && save_errno == lt->err)
	puts("\tOK");
      else
	{
	  puts("\tBAD");
	  if (l != (long int) lt->expect)
	    printf("  returns %ld, expected %ld\n",
		   l, (long int) lt->expect);
	  if (lt->left != *ep)
	    {
	      char exp1[5], exp2[5];
	      expand (exp1, *ep);
	      expand (exp2, lt->left);
	      printf ("  leaves '%s', expected '%s'\n", exp1, exp2);
	    }
	  if (save_errno != lt->err)
	    printf ("  errno %d (%s)  instead of %d (%s)\n",
		    save_errno, strerror (save_errno),
		    lt->err, strerror (lt->err));
	  status = 1;
	}
    }

  for (++lt; lt->str != NULL; lt++)
    {
      register unsigned long int ul;

      errno = 0;
      ul = strtoul (lt->str, &ep, lt->base);
      save_errno = errno;
      printf ("strtoul(\"%s\", , %d) test %u",
	      lt->str, lt->base, (unsigned int) (lt - tests));
      if (ul == lt->expect && *ep == lt->left && save_errno == lt->err)
	puts("\tOK");
      else
	{
	  puts ("\tBAD");
	  if (ul != lt->expect)
	    printf ("  returns %lu, expected %lu\n",
		    ul, lt->expect);
	  if (lt->left != *ep)
	    {
	      char exp1[5], exp2[5];
	      expand (exp1, *ep);
	      expand (exp2, lt->left);
	      printf ("  leaves '%s', expected '%s'\n", exp1, exp2);
	    }
	  if (save_errno != lt->err)
	    printf ("  errno %d (%s) instead of %d (%s)\n",
		    save_errno, strerror (save_errno),
		    lt->err, strerror (lt->err));
	  status = 1;
	}
    }

  return status ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void
expand (dst, c)
     char *dst;
     int c;
{
  if (isprint (c))
    {
      dst[0] = c;
      dst[1] = '\0';
    }
  else
    (void) sprintf (dst, "%#.3o", (unsigned int) c);
}
