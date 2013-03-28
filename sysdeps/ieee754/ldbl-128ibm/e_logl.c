/*							logll.c
 *
 * Natural logarithm for 128-bit long double precision.
 *
 *
 *
 * SYNOPSIS:
 *
 * long double x, y, logl();
 *
 * y = logl( x );
 *
 *
 *
 * DESCRIPTION:
 *
 * Returns the base e (2.718...) logarithm of x.
 *
 * The argument is separated into its exponent and fractional
 * parts.  Use of a lookup table increases the speed of the routine.
 * The program uses logarithms tabulated at intervals of 1/128 to
 * cover the domain from approximately 0.7 to 1.4.
 *
 * On the interval [-1/128, +1/128] the logarithm of 1+x is approximated by
 *     log(1+x) = x - 0.5 x^2 + x^3 P(x) .
 *
 *
 *
 * ACCURACY:
 *
 *                      Relative error:
 * arithmetic   domain     # trials      peak         rms
 *    IEEE   0.875, 1.125   100000      1.2e-34    4.1e-35
 *    IEEE   0.125, 8       100000      1.2e-34    4.1e-35
 *
 *
 * WARNING:
 *
 * This program uses integer operations on bit fields of floating-point
 * numbers.  It does not work with data structures other than the
 * structure assumed.
 *
 */

/* Copyright 2001 by Stephen L. Moshier <moshier@na-net.ornl.gov>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, see
    <http://www.gnu.org/licenses/>.  */

#include <math_private.h>

/* log(1+x) = x - .5 x^2 + x^3 l(x)
   -.0078125 <= x <= +.0078125
   peak relative error 1.2e-37 */
static const long double
l3 =   3.333333333333333333333333333333336096926E-1L,
l4 =  -2.499999999999999999999999999486853077002E-1L,
l5 =   1.999999999999999999999999998515277861905E-1L,
l6 =  -1.666666666666666666666798448356171665678E-1L,
l7 =   1.428571428571428571428808945895490721564E-1L,
l8 =  -1.249999999999999987884655626377588149000E-1L,
l9 =   1.111111111111111093947834982832456459186E-1L,
l10 = -1.000000000000532974938900317952530453248E-1L,
l11 =  9.090909090915566247008015301349979892689E-2L,
l12 = -8.333333211818065121250921925397567745734E-2L,
l13 =  7.692307559897661630807048686258659316091E-2L,
l14 = -7.144242754190814657241902218399056829264E-2L,
l15 =  6.668057591071739754844678883223432347481E-2L;

/* Lookup table of ln(t) - (t-1)
    t = 0.5 + (k+26)/128)
    k = 0, ..., 91   */
static const long double logtbl[92] = {
-5.5345593589352099112142921677820359632418E-2L,
-5.2108257402767124761784665198737642086148E-2L,
-4.8991686870576856279407775480686721935120E-2L,
-4.5993270766361228596215288742353061431071E-2L,
-4.3110481649613269682442058976885699556950E-2L,
-4.0340872319076331310838085093194799765520E-2L,
-3.7682072451780927439219005993827431503510E-2L,
-3.5131785416234343803903228503274262719586E-2L,
-3.2687785249045246292687241862699949178831E-2L,
-3.0347913785027239068190798397055267411813E-2L,
-2.8110077931525797884641940838507561326298E-2L,
-2.5972247078357715036426583294246819637618E-2L,
-2.3932450635346084858612873953407168217307E-2L,
-2.1988775689981395152022535153795155900240E-2L,
-2.0139364778244501615441044267387667496733E-2L,
-1.8382413762093794819267536615342902718324E-2L,
-1.6716169807550022358923589720001638093023E-2L,
-1.5138929457710992616226033183958974965355E-2L,
-1.3649036795397472900424896523305726435029E-2L,
-1.2244881690473465543308397998034325468152E-2L,
-1.0924898127200937840689817557742469105693E-2L,
-9.6875626072830301572839422532631079809328E-3L,
-8.5313926245226231463436209313499745894157E-3L,
-7.4549452072765973384933565912143044991706E-3L,
-6.4568155251217050991200599386801665681310E-3L,
-5.5356355563671005131126851708522185605193E-3L,
-4.6900728132525199028885749289712348829878E-3L,
-3.9188291218610470766469347968659624282519E-3L,
-3.2206394539524058873423550293617843896540E-3L,
-2.5942708080877805657374888909297113032132E-3L,
-2.0385211375711716729239156839929281289086E-3L,
-1.5522183228760777967376942769773768850872E-3L,
-1.1342191863606077520036253234446621373191E-3L,
-7.8340854719967065861624024730268350459991E-4L,
-4.9869831458030115699628274852562992756174E-4L,
-2.7902661731604211834685052867305795169688E-4L,
-1.2335696813916860754951146082826952093496E-4L,
-3.0677461025892873184042490943581654591817E-5L,
#define ZERO logtbl[38]
 0.0000000000000000000000000000000000000000E0L,
-3.0359557945051052537099938863236321874198E-5L,
-1.2081346403474584914595395755316412213151E-4L,
-2.7044071846562177120083903771008342059094E-4L,
-4.7834133324631162897179240322783590830326E-4L,
-7.4363569786340080624467487620270965403695E-4L,
-1.0654639687057968333207323853366578860679E-3L,
-1.4429854811877171341298062134712230604279E-3L,
-1.8753781835651574193938679595797367137975E-3L,
-2.3618380914922506054347222273705859653658E-3L,
-2.9015787624124743013946600163375853631299E-3L,
-3.4938307889254087318399313316921940859043E-3L,
-4.1378413103128673800485306215154712148146E-3L,
-4.8328735414488877044289435125365629849599E-3L,
-5.5782063183564351739381962360253116934243E-3L,
-6.3731336597098858051938306767880719015261E-3L,
-7.2169643436165454612058905294782949315193E-3L,
-8.1090214990427641365934846191367315083867E-3L,
-9.0486422112807274112838713105168375482480E-3L,
-1.0035177140880864314674126398350812606841E-2L,
-1.1067990155502102718064936259435676477423E-2L,
-1.2146457974158024928196575103115488672416E-2L,
-1.3269969823361415906628825374158424754308E-2L,
-1.4437927104692837124388550722759686270765E-2L,
-1.5649743073340777659901053944852735064621E-2L,
-1.6904842527181702880599758489058031645317E-2L,
-1.8202661505988007336096407340750378994209E-2L,
-1.9542647000370545390701192438691126552961E-2L,
-2.0924256670080119637427928803038530924742E-2L,
-2.2346958571309108496179613803760727786257E-2L,
-2.3810230892650362330447187267648486279460E-2L,
-2.5313561699385640380910474255652501521033E-2L,
-2.6856448685790244233704909690165496625399E-2L,
-2.8438398935154170008519274953860128449036E-2L,
-3.0058928687233090922411781058956589863039E-2L,
-3.1717563112854831855692484086486099896614E-2L,
-3.3413836095418743219397234253475252001090E-2L,
-3.5147290019036555862676702093393332533702E-2L,
-3.6917475563073933027920505457688955423688E-2L,
-3.8723951502862058660874073462456610731178E-2L,
-4.0566284516358241168330505467000838017425E-2L,
-4.2444048996543693813649967076598766917965E-2L,
-4.4356826869355401653098777649745233339196E-2L,
-4.6304207416957323121106944474331029996141E-2L,
-4.8285787106164123613318093945035804818364E-2L,
-5.0301169421838218987124461766244507342648E-2L,
-5.2349964705088137924875459464622098310997E-2L,
-5.4431789996103111613753440311680967840214E-2L,
-5.6546268881465384189752786409400404404794E-2L,
-5.8693031345788023909329239565012647817664E-2L,
-6.0871713627532018185577188079210189048340E-2L,
-6.3081958078862169742820420185833800925568E-2L,
-6.5323413029406789694910800219643791556918E-2L,
-6.7595732653791419081537811574227049288168E-2L
};

/* ln(2) = ln2a + ln2b with extended precision. */
static const long double
  ln2a = 6.93145751953125e-1L,
  ln2b = 1.4286068203094172321214581765680755001344E-6L;

static const long double
  ldbl_epsilon = 0x1p-106L;

long double
__ieee754_logl(long double x)
{
  long double z, y, w;
  ieee854_long_double_shape_type u, t;
  unsigned int m;
  int k, e;

  u.value = x;
  m = u.parts32.w0;

  /* Check for IEEE special cases.  */
  k = m & 0x7fffffff;
  /* log(0) = -infinity. */
  if ((k | u.parts32.w1 | (u.parts32.w2 & 0x7fffffff) | u.parts32.w3) == 0)
    {
      return -0.5L / ZERO;
    }
  /* log ( x < 0 ) = NaN */
  if (m & 0x80000000)
    {
      return (x - x) / ZERO;
    }
  /* log (infinity or NaN) */
  if (k >= 0x7ff00000)
    {
      return x + x;
    }

  /* On this interval the table is not used due to cancellation error.  */
  if ((x <= 1.0078125L) && (x >= 0.9921875L))
    {
      z = x - 1.0L;
      k = 64;
      t.value  = 1.0L;
      e = 0;
    }
  else
    {
      /* Extract exponent and reduce domain to 0.703125 <= u < 1.40625  */
      unsigned int w0;
      e = (int) (m >> 20) - (int) 0x3fe;
      m &= 0xfffff;
      w0 = m | 0x3fe00000;
      m |= 0x100000;
      /* Find lookup table index k from high order bits of the significand. */
      if (m < 0x168000)
	{
	  k = (m - 0xff000) >> 13;
	  /* t is the argument 0.5 + (k+26)/128
	     of the nearest item to u in the lookup table.  */
	  t.parts32.w0 = 0x3ff00000 + (k << 13);
	  t.parts32.w1 = 0;
	  t.parts32.w2 = 0;
	  t.parts32.w3 = 0;
	  w0 += 0x100000;
	  e -= 1;
	  k += 64;
	}
      else
	{
	  k = (m - 0xfe000) >> 14;
	  t.parts32.w0 = 0x3fe00000 + (k << 14);
	  t.parts32.w1 = 0;
	  t.parts32.w2 = 0;
	  t.parts32.w3 = 0;
	}
      u.value = __scalbnl (u.value, ((int) ((w0 - u.parts32.w0) * 2)) >> 21);
      /* log(u) = log( t u/t ) = log(t) + log(u/t)
	 log(t) is tabulated in the lookup table.
	 Express log(u/t) = log(1+z),  where z = u/t - 1 = (u-t)/t.
	 cf. Cody & Waite. */
      z = (u.value - t.value) / t.value;
    }
  /* Series expansion of log(1+z).  */
  w = z * z;
  /* Avoid spurious underflows.  */
  if (__glibc_unlikely(w <= ldbl_epsilon))
    y = 0.0L;
  else
    {
      y = ((((((((((((l15 * z
		  + l14) * z
		 + l13) * z
		+ l12) * z
	       + l11) * z
	      + l10) * z
	     + l9) * z
	    + l8) * z
	   + l7) * z
	  + l6) * z
	 + l5) * z
	+ l4) * z
       + l3) * z * w;
      y -= 0.5 * w;
    }
  y += e * ln2b;  /* Base 2 exponent offset times ln(2).  */
  y += z;
  y += logtbl[k-26]; /* log(t) - (t-1) */
  y += (t.value - 1.0L);
  y += e * ln2a;
  return y;
}
strong_alias (__ieee754_logl, __logl_finite)
