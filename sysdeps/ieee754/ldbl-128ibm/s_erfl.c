/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/* Modifications and expansions for 128-bit long double are
   Copyright (C) 2001 Stephen L. Moshier <moshier@na-net.ornl.gov>
   and are incorporated herein by permission of the author.  The author
   reserves the right to distribute this material elsewhere under different
   copying permissions.  These modifications are distributed here under
   the following terms:

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

/* double erf(double x)
 * double erfc(double x)
 *			     x
 *		      2      |\
 *     erf(x)  =  ---------  | exp(-t*t)dt
 *		   sqrt(pi) \|
 *			     0
 *
 *     erfc(x) =  1-erf(x)
 *  Note that
 *		erf(-x) = -erf(x)
 *		erfc(-x) = 2 - erfc(x)
 *
 * Method:
 *	1.  erf(x)  = x + x*R(x^2) for |x| in [0, 7/8]
 *	   Remark. The formula is derived by noting
 *          erf(x) = (2/sqrt(pi))*(x - x^3/3 + x^5/10 - x^7/42 + ....)
 *	   and that
 *          2/sqrt(pi) = 1.128379167095512573896158903121545171688
 *	   is close to one.
 *
 *      1a. erf(x)  = 1 - erfc(x), for |x| > 1.0
 *          erfc(x) = 1 - erf(x)  if |x| < 1/4
 *
 *      2. For |x| in [7/8, 1], let s = |x| - 1, and
 *         c = 0.84506291151 rounded to single (24 bits)
 *	erf(s + c)  = sign(x) * (c  + P1(s)/Q1(s))
 *	   Remark: here we use the taylor series expansion at x=1.
 *		erf(1+s) = erf(1) + s*Poly(s)
 *			 = 0.845.. + P1(s)/Q1(s)
 *	   Note that |P1/Q1|< 0.078 for x in [0.84375,1.25]
 *
 *      3. For x in [1/4, 5/4],
 *	erfc(s + const)  = erfc(const)  + s P1(s)/Q1(s)
 *              for const = 1/4, 3/8, ..., 9/8
 *              and 0 <= s <= 1/8 .
 *
 *      4. For x in [5/4, 107],
 *	erfc(x) = (1/x)*exp(-x*x-0.5625 + R(z))
 *              z=1/x^2
 *         The interval is partitioned into several segments
 *         of width 1/8 in 1/x.
 *	erf(x) = 1.0 - erfc(x) if x < 25.6283 else
 *	erf(x) = sign(x)*(1.0 - tiny)
 *
 *      Note1:
 *	   To compute exp(-x*x-0.5625+R/S), let s be a single
 *	   precision number and s := x; then
 *		-x*x = -s*s + (s-x)*(s+x)
 *	        exp(-x*x-0.5626+R/S) =
 *			exp(-s*s-0.5625)*exp((s-x)*(s+x)+R/S);
 *      Note2:
 *	   Here 4 and 5 make use of the asymptotic series
 *			  exp(-x*x)
 *		erfc(x) ~ ---------- * ( 1 + Poly(1/x^2) )
 *			  x*sqrt(pi)
 *
 *      Note3:
 * 	   For x higher than 25.6283, erf(x) underflows.
 *
 *      5. For inf > x >= 107
 *	erf(x)  = sign(x) *(1 - tiny)  (raise inexact)
 *	erfc(x) = tiny*tiny (raise underflow) if x > 0
 *			= 2 - tiny if x<0
 *
 *      7. Special case:
 *	erf(0)  = 0, erf(inf)  = 1, erf(-inf) = -1,
 *	erfc(0) = 1, erfc(inf) = 0, erfc(-inf) = 2,
 *		erfc/erf(NaN) is NaN
 */

#include <errno.h>
#include <float.h>
#include <math.h>
#include <math_private.h>
#include <math_ldbl_opt.h>

/* Evaluate P[n] x^n  +  P[n-1] x^(n-1)  +  ...  +  P[0] */

static long double
neval (long double x, const long double *p, int n)
{
  long double y;

  p += n;
  y = *p--;
  do
    {
      y = y * x + *p--;
    }
  while (--n > 0);
  return y;
}


/* Evaluate x^n+1  +  P[n] x^(n)  +  P[n-1] x^(n-1)  +  ...  +  P[0] */

static long double
deval (long double x, const long double *p, int n)
{
  long double y;

  p += n;
  y = x + *p--;
  do
    {
      y = y * x + *p--;
    }
  while (--n > 0);
  return y;
}



static const long double
tiny = 1e-300L,
  half = 0.5L,
  one = 1.0L,
  two = 2.0L,
  /* 2/sqrt(pi) - 1 */
  efx = 1.2837916709551257389615890312154517168810E-1L;


/* erf(x)  = x  + x R(x^2)
   0 <= x <= 7/8
   Peak relative error 1.8e-35  */
#define NTN1 8
static const long double TN1[NTN1 + 1] =
{
 -3.858252324254637124543172907442106422373E10L,
  9.580319248590464682316366876952214879858E10L,
  1.302170519734879977595901236693040544854E10L,
  2.922956950426397417800321486727032845006E9L,
  1.764317520783319397868923218385468729799E8L,
  1.573436014601118630105796794840834145120E7L,
  4.028077380105721388745632295157816229289E5L,
  1.644056806467289066852135096352853491530E4L,
  3.390868480059991640235675479463287886081E1L
};
#define NTD1 8
static const long double TD1[NTD1 + 1] =
{
  -3.005357030696532927149885530689529032152E11L,
  -1.342602283126282827411658673839982164042E11L,
  -2.777153893355340961288511024443668743399E10L,
  -3.483826391033531996955620074072768276974E9L,
  -2.906321047071299585682722511260895227921E8L,
  -1.653347985722154162439387878512427542691E7L,
  -6.245520581562848778466500301865173123136E5L,
  -1.402124304177498828590239373389110545142E4L,
  -1.209368072473510674493129989468348633579E2L
/* 1.0E0 */
};


/* erf(z+1)  = erf_const + P(z)/Q(z)
   -.125 <= z <= 0
   Peak relative error 7.3e-36  */
static const long double erf_const = 0.845062911510467529296875L;
#define NTN2 8
static const long double TN2[NTN2 + 1] =
{
 -4.088889697077485301010486931817357000235E1L,
  7.157046430681808553842307502826960051036E3L,
 -2.191561912574409865550015485451373731780E3L,
  2.180174916555316874988981177654057337219E3L,
  2.848578658049670668231333682379720943455E2L,
  1.630362490952512836762810462174798925274E2L,
  6.317712353961866974143739396865293596895E0L,
  2.450441034183492434655586496522857578066E1L,
  5.127662277706787664956025545897050896203E-1L
};
#define NTD2 8
static const long double TD2[NTD2 + 1] =
{
  1.731026445926834008273768924015161048885E4L,
  1.209682239007990370796112604286048173750E4L,
  1.160950290217993641320602282462976163857E4L,
  5.394294645127126577825507169061355698157E3L,
  2.791239340533632669442158497532521776093E3L,
  8.989365571337319032943005387378993827684E2L,
  2.974016493766349409725385710897298069677E2L,
  6.148192754590376378740261072533527271947E1L,
  1.178502892490738445655468927408440847480E1L
 /* 1.0E0 */
};


/* erfc(x + 0.25) = erfc(0.25) + x R(x)
   0 <= x < 0.125
   Peak relative error 1.4e-35  */
#define NRNr13 8
static const long double RNr13[NRNr13 + 1] =
{
 -2.353707097641280550282633036456457014829E3L,
  3.871159656228743599994116143079870279866E2L,
 -3.888105134258266192210485617504098426679E2L,
 -2.129998539120061668038806696199343094971E1L,
 -8.125462263594034672468446317145384108734E1L,
  8.151549093983505810118308635926270319660E0L,
 -5.033362032729207310462422357772568553670E0L,
 -4.253956621135136090295893547735851168471E-2L,
 -8.098602878463854789780108161581050357814E-2L
};
#define NRDr13 7
static const long double RDr13[NRDr13 + 1] =
{
  2.220448796306693503549505450626652881752E3L,
  1.899133258779578688791041599040951431383E2L,
  1.061906712284961110196427571557149268454E3L,
  7.497086072306967965180978101974566760042E1L,
  2.146796115662672795876463568170441327274E2L,
  1.120156008362573736664338015952284925592E1L,
  2.211014952075052616409845051695042741074E1L,
  6.469655675326150785692908453094054988938E-1L
 /* 1.0E0 */
};
/* erfc(0.25) = C13a + C13b to extra precision.  */
static const long double C13a = 0.723663330078125L;
static const long double C13b = 1.0279753638067014931732235184287934646022E-5L;


/* erfc(x + 0.375) = erfc(0.375) + x R(x)
   0 <= x < 0.125
   Peak relative error 1.2e-35  */
#define NRNr14 8
static const long double RNr14[NRNr14 + 1] =
{
 -2.446164016404426277577283038988918202456E3L,
  6.718753324496563913392217011618096698140E2L,
 -4.581631138049836157425391886957389240794E2L,
 -2.382844088987092233033215402335026078208E1L,
 -7.119237852400600507927038680970936336458E1L,
  1.313609646108420136332418282286454287146E1L,
 -6.188608702082264389155862490056401365834E0L,
 -2.787116601106678287277373011101132659279E-2L,
 -2.230395570574153963203348263549700967918E-2L
};
#define NRDr14 7
static const long double RDr14[NRDr14 + 1] =
{
  2.495187439241869732696223349840963702875E3L,
  2.503549449872925580011284635695738412162E2L,
  1.159033560988895481698051531263861842461E3L,
  9.493751466542304491261487998684383688622E1L,
  2.276214929562354328261422263078480321204E2L,
  1.367697521219069280358984081407807931847E1L,
  2.276988395995528495055594829206582732682E1L,
  7.647745753648996559837591812375456641163E-1L
 /* 1.0E0 */
};
/* erfc(0.375) = C14a + C14b to extra precision.  */
static const long double C14a = 0.5958709716796875L;
static const long double C14b = 1.2118885490201676174914080878232469565953E-5L;

/* erfc(x + 0.5) = erfc(0.5) + x R(x)
   0 <= x < 0.125
   Peak relative error 4.7e-36  */
#define NRNr15 8
static const long double RNr15[NRNr15 + 1] =
{
 -2.624212418011181487924855581955853461925E3L,
  8.473828904647825181073831556439301342756E2L,
 -5.286207458628380765099405359607331669027E2L,
 -3.895781234155315729088407259045269652318E1L,
 -6.200857908065163618041240848728398496256E1L,
  1.469324610346924001393137895116129204737E1L,
 -6.961356525370658572800674953305625578903E0L,
  5.145724386641163809595512876629030548495E-3L,
  1.990253655948179713415957791776180406812E-2L
};
#define NRDr15 7
static const long double RDr15[NRDr15 + 1] =
{
  2.986190760847974943034021764693341524962E3L,
  5.288262758961073066335410218650047725985E2L,
  1.363649178071006978355113026427856008978E3L,
  1.921707975649915894241864988942255320833E2L,
  2.588651100651029023069013885900085533226E2L,
  2.628752920321455606558942309396855629459E1L,
  2.455649035885114308978333741080991380610E1L,
  1.378826653595128464383127836412100939126E0L
  /* 1.0E0 */
};
/* erfc(0.5) = C15a + C15b to extra precision.  */
static const long double C15a = 0.4794921875L;
static const long double C15b = 7.9346869534623172533461080354712635484242E-6L;

/* erfc(x + 0.625) = erfc(0.625) + x R(x)
   0 <= x < 0.125
   Peak relative error 5.1e-36  */
#define NRNr16 8
static const long double RNr16[NRNr16 + 1] =
{
 -2.347887943200680563784690094002722906820E3L,
  8.008590660692105004780722726421020136482E2L,
 -5.257363310384119728760181252132311447963E2L,
 -4.471737717857801230450290232600243795637E1L,
 -4.849540386452573306708795324759300320304E1L,
  1.140885264677134679275986782978655952843E1L,
 -6.731591085460269447926746876983786152300E0L,
  1.370831653033047440345050025876085121231E-1L,
  2.022958279982138755020825717073966576670E-2L,
};
#define NRDr16 7
static const long double RDr16[NRDr16 + 1] =
{
  3.075166170024837215399323264868308087281E3L,
  8.730468942160798031608053127270430036627E2L,
  1.458472799166340479742581949088453244767E3L,
  3.230423687568019709453130785873540386217E2L,
  2.804009872719893612081109617983169474655E2L,
  4.465334221323222943418085830026979293091E1L,
  2.612723259683205928103787842214809134746E1L,
  2.341526751185244109722204018543276124997E0L,
  /* 1.0E0 */
};
/* erfc(0.625) = C16a + C16b to extra precision.  */
static const long double C16a = 0.3767547607421875L;
static const long double C16b = 4.3570693945275513594941232097252997287766E-6L;

/* erfc(x + 0.75) = erfc(0.75) + x R(x)
   0 <= x < 0.125
   Peak relative error 1.7e-35  */
#define NRNr17 8
static const long double RNr17[NRNr17 + 1] =
{
  -1.767068734220277728233364375724380366826E3L,
  6.693746645665242832426891888805363898707E2L,
  -4.746224241837275958126060307406616817753E2L,
  -2.274160637728782675145666064841883803196E1L,
  -3.541232266140939050094370552538987982637E1L,
  6.988950514747052676394491563585179503865E0L,
  -5.807687216836540830881352383529281215100E0L,
  3.631915988567346438830283503729569443642E-1L,
  -1.488945487149634820537348176770282391202E-2L
};
#define NRDr17 7
static const long double RDr17[NRDr17 + 1] =
{
  2.748457523498150741964464942246913394647E3L,
  1.020213390713477686776037331757871252652E3L,
  1.388857635935432621972601695296561952738E3L,
  3.903363681143817750895999579637315491087E2L,
  2.784568344378139499217928969529219886578E2L,
  5.555800830216764702779238020065345401144E1L,
  2.646215470959050279430447295801291168941E1L,
  2.984905282103517497081766758550112011265E0L,
  /* 1.0E0 */
};
/* erfc(0.75) = C17a + C17b to extra precision.  */
static const long double C17a = 0.2888336181640625L;
static const long double C17b = 1.0748182422368401062165408589222625794046E-5L;


/* erfc(x + 0.875) = erfc(0.875) + x R(x)
   0 <= x < 0.125
   Peak relative error 2.2e-35  */
#define NRNr18 8
static const long double RNr18[NRNr18 + 1] =
{
 -1.342044899087593397419622771847219619588E3L,
  6.127221294229172997509252330961641850598E2L,
 -4.519821356522291185621206350470820610727E2L,
  1.223275177825128732497510264197915160235E1L,
 -2.730789571382971355625020710543532867692E1L,
  4.045181204921538886880171727755445395862E0L,
 -4.925146477876592723401384464691452700539E0L,
  5.933878036611279244654299924101068088582E-1L,
 -5.557645435858916025452563379795159124753E-2L
};
#define NRDr18 7
static const long double RDr18[NRDr18 + 1] =
{
  2.557518000661700588758505116291983092951E3L,
  1.070171433382888994954602511991940418588E3L,
  1.344842834423493081054489613250688918709E3L,
  4.161144478449381901208660598266288188426E2L,
  2.763670252219855198052378138756906980422E2L,
  5.998153487868943708236273854747564557632E1L,
  2.657695108438628847733050476209037025318E1L,
  3.252140524394421868923289114410336976512E0L,
  /* 1.0E0 */
};
/* erfc(0.875) = C18a + C18b to extra precision.  */
static const long double C18a = 0.215911865234375L;
static const long double C18b = 1.3073705765341685464282101150637224028267E-5L;

/* erfc(x + 1.0) = erfc(1.0) + x R(x)
   0 <= x < 0.125
   Peak relative error 1.6e-35  */
#define NRNr19 8
static const long double RNr19[NRNr19 + 1] =
{
 -1.139180936454157193495882956565663294826E3L,
  6.134903129086899737514712477207945973616E2L,
 -4.628909024715329562325555164720732868263E2L,
  4.165702387210732352564932347500364010833E1L,
 -2.286979913515229747204101330405771801610E1L,
  1.870695256449872743066783202326943667722E0L,
 -4.177486601273105752879868187237000032364E0L,
  7.533980372789646140112424811291782526263E-1L,
 -8.629945436917752003058064731308767664446E-2L
};
#define NRDr19 7
static const long double RDr19[NRDr19 + 1] =
{
  2.744303447981132701432716278363418643778E3L,
  1.266396359526187065222528050591302171471E3L,
  1.466739461422073351497972255511919814273E3L,
  4.868710570759693955597496520298058147162E2L,
  2.993694301559756046478189634131722579643E2L,
  6.868976819510254139741559102693828237440E1L,
  2.801505816247677193480190483913753613630E1L,
  3.604439909194350263552750347742663954481E0L,
  /* 1.0E0 */
};
/* erfc(1.0) = C19a + C19b to extra precision.  */
static const long double C19a = 0.15728759765625L;
static const long double C19b = 1.1609394035130658779364917390740703933002E-5L;

/* erfc(x + 1.125) = erfc(1.125) + x R(x)
   0 <= x < 0.125
   Peak relative error 3.6e-36  */
#define NRNr20 8
static const long double RNr20[NRNr20 + 1] =
{
 -9.652706916457973956366721379612508047640E2L,
  5.577066396050932776683469951773643880634E2L,
 -4.406335508848496713572223098693575485978E2L,
  5.202893466490242733570232680736966655434E1L,
 -1.931311847665757913322495948705563937159E1L,
 -9.364318268748287664267341457164918090611E-2L,
 -3.306390351286352764891355375882586201069E0L,
  7.573806045289044647727613003096916516475E-1L,
 -9.611744011489092894027478899545635991213E-2L
};
#define NRDr20 7
static const long double RDr20[NRDr20 + 1] =
{
  3.032829629520142564106649167182428189014E3L,
  1.659648470721967719961167083684972196891E3L,
  1.703545128657284619402511356932569292535E3L,
  6.393465677731598872500200253155257708763E2L,
  3.489131397281030947405287112726059221934E2L,
  8.848641738570783406484348434387611713070E1L,
  3.132269062552392974833215844236160958502E1L,
  4.430131663290563523933419966185230513168E0L
 /* 1.0E0 */
};
/* erfc(1.125) = C20a + C20b to extra precision.  */
static const long double C20a = 0.111602783203125L;
static const long double C20b = 8.9850951672359304215530728365232161564636E-6L;

/* erfc(1/x) = 1/x exp (-1/x^2 - 0.5625 + R(1/x^2))
   7/8 <= 1/x < 1
   Peak relative error 1.4e-35  */
#define NRNr8 9
static const long double RNr8[NRNr8 + 1] =
{
  3.587451489255356250759834295199296936784E1L,
  5.406249749087340431871378009874875889602E2L,
  2.931301290625250886238822286506381194157E3L,
  7.359254185241795584113047248898753470923E3L,
  9.201031849810636104112101947312492532314E3L,
  5.749697096193191467751650366613289284777E3L,
  1.710415234419860825710780802678697889231E3L,
  2.150753982543378580859546706243022719599E2L,
  8.740953582272147335100537849981160931197E0L,
  4.876422978828717219629814794707963640913E-2L
};
#define NRDr8 8
static const long double RDr8[NRDr8 + 1] =
{
  6.358593134096908350929496535931630140282E1L,
  9.900253816552450073757174323424051765523E2L,
  5.642928777856801020545245437089490805186E3L,
  1.524195375199570868195152698617273739609E4L,
  2.113829644500006749947332935305800887345E4L,
  1.526438562626465706267943737310282977138E4L,
  5.561370922149241457131421914140039411782E3L,
  9.394035530179705051609070428036834496942E2L,
  6.147019596150394577984175188032707343615E1L
  /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp (-1/x^2 - 0.5625 + R(1/x^2))
   0.75 <= 1/x <= 0.875
   Peak relative error 2.0e-36  */
#define NRNr7 9
static const long double RNr7[NRNr7 + 1] =
{
 1.686222193385987690785945787708644476545E1L,
 1.178224543567604215602418571310612066594E3L,
 1.764550584290149466653899886088166091093E4L,
 1.073758321890334822002849369898232811561E5L,
 3.132840749205943137619839114451290324371E5L,
 4.607864939974100224615527007793867585915E5L,
 3.389781820105852303125270837910972384510E5L,
 1.174042187110565202875011358512564753399E5L,
 1.660013606011167144046604892622504338313E4L,
 6.700393957480661937695573729183733234400E2L
};
#define NRDr7 9
static const long double RDr7[NRDr7 + 1] =
{
-1.709305024718358874701575813642933561169E3L,
-3.280033887481333199580464617020514788369E4L,
-2.345284228022521885093072363418750835214E5L,
-8.086758123097763971926711729242327554917E5L,
-1.456900414510108718402423999575992450138E6L,
-1.391654264881255068392389037292702041855E6L,
-6.842360801869939983674527468509852583855E5L,
-1.597430214446573566179675395199807533371E5L,
-1.488876130609876681421645314851760773480E4L,
-3.511762950935060301403599443436465645703E2L
 /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   5/8 <= 1/x < 3/4
   Peak relative error 1.9e-35  */
#define NRNr6 9
static const long double RNr6[NRNr6 + 1] =
{
 1.642076876176834390623842732352935761108E0L,
 1.207150003611117689000664385596211076662E2L,
 2.119260779316389904742873816462800103939E3L,
 1.562942227734663441801452930916044224174E4L,
 5.656779189549710079988084081145693580479E4L,
 1.052166241021481691922831746350942786299E5L,
 9.949798524786000595621602790068349165758E4L,
 4.491790734080265043407035220188849562856E4L,
 8.377074098301530326270432059434791287601E3L,
 4.506934806567986810091824791963991057083E2L
};
#define NRDr6 9
static const long double RDr6[NRDr6 + 1] =
{
-1.664557643928263091879301304019826629067E2L,
-3.800035902507656624590531122291160668452E3L,
-3.277028191591734928360050685359277076056E4L,
-1.381359471502885446400589109566587443987E5L,
-3.082204287382581873532528989283748656546E5L,
-3.691071488256738343008271448234631037095E5L,
-2.300482443038349815750714219117566715043E5L,
-6.873955300927636236692803579555752171530E4L,
-8.262158817978334142081581542749986845399E3L,
-2.517122254384430859629423488157361983661E2L
 /* 1.00 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   1/2 <= 1/x < 5/8
   Peak relative error 4.6e-36  */
#define NRNr5 10
static const long double RNr5[NRNr5 + 1] =
{
-3.332258927455285458355550878136506961608E-3L,
-2.697100758900280402659586595884478660721E-1L,
-6.083328551139621521416618424949137195536E0L,
-6.119863528983308012970821226810162441263E1L,
-3.176535282475593173248810678636522589861E2L,
-8.933395175080560925809992467187963260693E2L,
-1.360019508488475978060917477620199499560E3L,
-1.075075579828188621541398761300910213280E3L,
-4.017346561586014822824459436695197089916E2L,
-5.857581368145266249509589726077645791341E1L,
-2.077715925587834606379119585995758954399E0L
};
#define NRDr5 9
static const long double RDr5[NRDr5 + 1] =
{
 3.377879570417399341550710467744693125385E-1L,
 1.021963322742390735430008860602594456187E1L,
 1.200847646592942095192766255154827011939E2L,
 7.118915528142927104078182863387116942836E2L,
 2.318159380062066469386544552429625026238E3L,
 4.238729853534009221025582008928765281620E3L,
 4.279114907284825886266493994833515580782E3L,
 2.257277186663261531053293222591851737504E3L,
 5.570475501285054293371908382916063822957E2L,
 5.142189243856288981145786492585432443560E1L
 /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   3/8 <= 1/x < 1/2
   Peak relative error 2.0e-36  */
#define NRNr4 10
static const long double RNr4[NRNr4 + 1] =
{
 3.258530712024527835089319075288494524465E-3L,
 2.987056016877277929720231688689431056567E-1L,
 8.738729089340199750734409156830371528862E0L,
 1.207211160148647782396337792426311125923E2L,
 8.997558632489032902250523945248208224445E2L,
 3.798025197699757225978410230530640879762E3L,
 9.113203668683080975637043118209210146846E3L,
 1.203285891339933238608683715194034900149E4L,
 8.100647057919140328536743641735339740855E3L,
 2.383888249907144945837976899822927411769E3L,
 2.127493573166454249221983582495245662319E2L
};
#define NRDr4 10
static const long double RDr4[NRDr4 + 1] =
{
-3.303141981514540274165450687270180479586E-1L,
-1.353768629363605300707949368917687066724E1L,
-2.206127630303621521950193783894598987033E2L,
-1.861800338758066696514480386180875607204E3L,
-8.889048775872605708249140016201753255599E3L,
-2.465888106627948210478692168261494857089E4L,
-3.934642211710774494879042116768390014289E4L,
-3.455077258242252974937480623730228841003E4L,
-1.524083977439690284820586063729912653196E4L,
-2.810541887397984804237552337349093953857E3L,
-1.343929553541159933824901621702567066156E2L
 /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   1/4 <= 1/x < 3/8
   Peak relative error 8.4e-37  */
#define NRNr3 11
static const long double RNr3[NRNr3 + 1] =
{
-1.952401126551202208698629992497306292987E-6L,
-2.130881743066372952515162564941682716125E-4L,
-8.376493958090190943737529486107282224387E-3L,
-1.650592646560987700661598877522831234791E-1L,
-1.839290818933317338111364667708678163199E0L,
-1.216278715570882422410442318517814388470E1L,
-4.818759344462360427612133632533779091386E1L,
-1.120994661297476876804405329172164436784E2L,
-1.452850765662319264191141091859300126931E2L,
-9.485207851128957108648038238656777241333E1L,
-2.563663855025796641216191848818620020073E1L,
-1.787995944187565676837847610706317833247E0L
};
#define NRDr3 10
static const long double RDr3[NRDr3 + 1] =
{
 1.979130686770349481460559711878399476903E-4L,
 1.156941716128488266238105813374635099057E-2L,
 2.752657634309886336431266395637285974292E-1L,
 3.482245457248318787349778336603569327521E0L,
 2.569347069372696358578399521203959253162E1L,
 1.142279000180457419740314694631879921561E2L,
 3.056503977190564294341422623108332700840E2L,
 4.780844020923794821656358157128719184422E2L,
 4.105972727212554277496256802312730410518E2L,
 1.724072188063746970865027817017067646246E2L,
 2.815939183464818198705278118326590370435E1L
 /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   1/8 <= 1/x < 1/4
   Peak relative error 1.5e-36  */
#define NRNr2 11
static const long double RNr2[NRNr2 + 1] =
{
-2.638914383420287212401687401284326363787E-8L,
-3.479198370260633977258201271399116766619E-6L,
-1.783985295335697686382487087502222519983E-4L,
-4.777876933122576014266349277217559356276E-3L,
-7.450634738987325004070761301045014986520E-2L,
-7.068318854874733315971973707247467326619E-1L,
-4.113919921935944795764071670806867038732E0L,
-1.440447573226906222417767283691888875082E1L,
-2.883484031530718428417168042141288943905E1L,
-2.990886974328476387277797361464279931446E1L,
-1.325283914915104866248279787536128997331E1L,
-1.572436106228070195510230310658206154374E0L
};
#define NRDr2 10
static const long double RDr2[NRDr2 + 1] =
{
 2.675042728136731923554119302571867799673E-6L,
 2.170997868451812708585443282998329996268E-4L,
 7.249969752687540289422684951196241427445E-3L,
 1.302040375859768674620410563307838448508E-1L,
 1.380202483082910888897654537144485285549E0L,
 8.926594113174165352623847870299170069350E0L,
 3.521089584782616472372909095331572607185E1L,
 8.233547427533181375185259050330809105570E1L,
 1.072971579885803033079469639073292840135E2L,
 6.943803113337964469736022094105143158033E1L,
 1.775695341031607738233608307835017282662E1L
 /* 1.0E0 */
};

/* erfc(1/x) = 1/x exp(-1/x^2 - 0.5625 + R(1/x^2))
   1/128 <= 1/x < 1/8
   Peak relative error 2.2e-36  */
#define NRNr1 9
static const long double RNr1[NRNr1 + 1] =
{
-4.250780883202361946697751475473042685782E-8L,
-5.375777053288612282487696975623206383019E-6L,
-2.573645949220896816208565944117382460452E-4L,
-6.199032928113542080263152610799113086319E-3L,
-8.262721198693404060380104048479916247786E-2L,
-6.242615227257324746371284637695778043982E-1L,
-2.609874739199595400225113299437099626386E0L,
-5.581967563336676737146358534602770006970E0L,
-5.124398923356022609707490956634280573882E0L,
-1.290865243944292370661544030414667556649E0L
};
#define NRDr1 8
static const long double RDr1[NRDr1 + 1] =
{
 4.308976661749509034845251315983612976224E-6L,
 3.265390126432780184125233455960049294580E-4L,
 9.811328839187040701901866531796570418691E-3L,
 1.511222515036021033410078631914783519649E-1L,
 1.289264341917429958858379585970225092274E0L,
 6.147640356182230769548007536914983522270E0L,
 1.573966871337739784518246317003956180750E1L,
 1.955534123435095067199574045529218238263E1L,
 9.472613121363135472247929109615785855865E0L
  /* 1.0E0 */
};


long double
__erfl (long double x)
{
  long double a, y, z;
  int32_t i, ix, hx;
  double xhi;

  xhi = ldbl_high (x);
  GET_HIGH_WORD (hx, xhi);
  ix = hx & 0x7fffffff;

  if (ix >= 0x7ff00000)
    {				/* erf(nan)=nan */
      i = ((uint32_t) hx >> 31) << 1;
      return (long double) (1 - i) + one / x;	/* erf(+-inf)=+-1 */
    }

  if (ix >= 0x3ff00000) /* |x| >= 1.0 */
    {
      if (ix >= 0x4039A0DE)
	{
	/* __erfcl (x) underflows if x > 25.6283 */
	  if ((hx & 0x80000000) == 0)
	    return one-tiny;
	  else
	    return tiny-one;
	}
      else
	{
	  y = __erfcl (x);
	  return (one - y);
	}
    }
  a = x;
  if ((hx & 0x80000000) != 0)
    a = -a;
  z = x * x;
  if (ix < 0x3fec0000)  /* a < 0.875 */
    {
      if (ix < 0x3c600000) /* |x|<2**-57 */
	{
	  if (ix < 0x00800000)
	    {
	      /* erf (-0) = -0.  Unfortunately, for IBM extended double
		 0.0625 * (16.0 * x + (16.0 * efx) * x) for x = -0
		 evaluates to 0.  */
	      if (x == 0)
		return x;
	      long double ret = 0.0625 * (16.0 * x + (16.0 * efx) * x);
	      if (fabsl (ret) < LDBL_MIN)
		{
		  long double force_underflow = ret * ret;
		  math_force_eval (force_underflow);
		}
	      return ret;
	    }
	  return x + efx * x;
	}
      y = a + a * neval (z, TN1, NTN1) / deval (z, TD1, NTD1);
    }
  else
    {
      a = a - one;
      y = erf_const + neval (a, TN2, NTN2) / deval (a, TD2, NTD2);
    }

  if (hx & 0x80000000) /* x < 0 */
    y = -y;
  return( y );
}

long_double_symbol (libm, __erfl, erfl);
long double
__erfcl (long double x)
{
  long double y, z, p, r;
  int32_t i, ix;
  uint32_t hx;
  double xhi;

  xhi = ldbl_high (x);
  GET_HIGH_WORD (hx, xhi);
  ix = hx & 0x7fffffff;

  if (ix >= 0x7ff00000)
    {				/* erfc(nan)=nan */
      /* erfc(+-inf)=0,2 */
      return (long double) ((hx >> 31) << 1) + one / x;
    }

  if (ix < 0x3fd00000) /* |x| <1/4 */
    {
      if (ix < 0x38d00000) /* |x|<2**-114 */
	return one - x;
      return one - __erfl (x);
    }
  if (ix < 0x3ff40000) /* 1.25 */
    {
      if ((hx & 0x80000000) != 0)
	x = -x;
      i = 8.0 * x;
      switch (i)
	{
	case 2:
	  z = x - 0.25L;
	  y = C13b + z * neval (z, RNr13, NRNr13) / deval (z, RDr13, NRDr13);
	  y += C13a;
	  break;
	case 3:
	  z = x - 0.375L;
	  y = C14b + z * neval (z, RNr14, NRNr14) / deval (z, RDr14, NRDr14);
	  y += C14a;
	  break;
	case 4:
	  z = x - 0.5L;
	  y = C15b + z * neval (z, RNr15, NRNr15) / deval (z, RDr15, NRDr15);
	  y += C15a;
	  break;
	case 5:
	  z = x - 0.625L;
	  y = C16b + z * neval (z, RNr16, NRNr16) / deval (z, RDr16, NRDr16);
	  y += C16a;
	  break;
	case 6:
	  z = x - 0.75L;
	  y = C17b + z * neval (z, RNr17, NRNr17) / deval (z, RDr17, NRDr17);
	  y += C17a;
	  break;
	case 7:
	  z = x - 0.875L;
	  y = C18b + z * neval (z, RNr18, NRNr18) / deval (z, RDr18, NRDr18);
	  y += C18a;
	  break;
	case 8:
	  z = x - 1.0L;
	  y = C19b + z * neval (z, RNr19, NRNr19) / deval (z, RDr19, NRDr19);
	  y += C19a;
	  break;
	default: /* i == 9.  */
	  z = x - 1.125L;
	  y = C20b + z * neval (z, RNr20, NRNr20) / deval (z, RDr20, NRDr20);
	  y += C20a;
	  break;
	}
      if (hx & 0x80000000)
	y = 2.0L - y;
      return y;
    }
  /* 1.25 < |x| < 107 */
  if (ix < 0x405ac000)
    {
      /* x < -9 */
      if (hx >= 0xc0220000)
	return two - tiny;

      if ((hx & 0x80000000) != 0)
	x = -x;
      z = one / (x * x);
      i = 8.0 / x;
      switch (i)
	{
	default:
	case 0:
	  p = neval (z, RNr1, NRNr1) / deval (z, RDr1, NRDr1);
	  break;
	case 1:
	  p = neval (z, RNr2, NRNr2) / deval (z, RDr2, NRDr2);
	  break;
	case 2:
	  p = neval (z, RNr3, NRNr3) / deval (z, RDr3, NRDr3);
	  break;
	case 3:
	  p = neval (z, RNr4, NRNr4) / deval (z, RDr4, NRDr4);
	  break;
	case 4:
	  p = neval (z, RNr5, NRNr5) / deval (z, RDr5, NRDr5);
	  break;
	case 5:
	  p = neval (z, RNr6, NRNr6) / deval (z, RDr6, NRDr6);
	  break;
	case 6:
	  p = neval (z, RNr7, NRNr7) / deval (z, RDr7, NRDr7);
	  break;
	case 7:
	  p = neval (z, RNr8, NRNr8) / deval (z, RDr8, NRDr8);
	  break;
	}
      z = (float) x;
      r = __ieee754_expl (-z * z - 0.5625) *
	__ieee754_expl ((z - x) * (z + x) + p);
      if ((hx & 0x80000000) == 0)
	{
	  long double ret = r / x;
	  if (ret == 0)
	    __set_errno (ERANGE);
	  return ret;
	}
      else
	return two - r / x;
    }
  else
    {
      if ((hx & 0x80000000) == 0)
	{
	  __set_errno (ERANGE);
	  return tiny * tiny;
	}
      else
	return two - tiny;
    }
}

long_double_symbol (libm, __erfcl, erfcl);
