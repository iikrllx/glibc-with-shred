/*							j0l.c
 *
 *	Bessel function of order zero
 *
 *
 *
 * SYNOPSIS:
 *
 * long double x, y, j0l();
 *
 * y = j0l( x );
 *
 *
 *
 * DESCRIPTION:
 *
 * Returns Bessel function of first kind, order zero of the argument.
 *
 * The domain is divided into two major intervals [0, 2] and
 * (2, infinity). In the first interval the rational approximation
 * is J0(x) = 1 - x^2 / 4 + x^4 R(x^2)
 * The second interval is further partitioned into eight equal segments
 * of 1/x.
 *
 * J0(x) = sqrt(2/(pi x)) (P0(x) cos(X) - Q0(x) sin(X)),
 * X = x - pi/4,
 *
 * and the auxiliary functions are given by
 *
 * J0(x)cos(X) + Y0(x)sin(X) = sqrt( 2/(pi x)) P0(x),
 * P0(x) = 1 + 1/x^2 R(1/x^2)
 *
 * Y0(x)cos(X) - J0(x)sin(X) = sqrt( 2/(pi x)) Q0(x),
 * Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
 *
 *
 *
 * ACCURACY:
 *
 *                      Absolute error:
 * arithmetic   domain      # trials      peak         rms
 *    IEEE      0, 30       100000      1.7e-34      2.4e-35
 *
 *
 */

/*							y0l.c
 *
 *	Bessel function of the second kind, order zero
 *
 *
 *
 * SYNOPSIS:
 *
 * double x, y, y0l();
 *
 * y = y0l( x );
 *
 *
 *
 * DESCRIPTION:
 *
 * Returns Bessel function of the second kind, of order
 * zero, of the argument.
 *
 * The approximation is the same as for J0(x), and
 * Y0(x) = sqrt(2/(pi x)) (P0(x) sin(X) + Q0(x) cos(X)).
 *
 * ACCURACY:
 *
 *  Absolute error, when y0(x) < 1; else relative error:
 *
 * arithmetic   domain     # trials      peak         rms
 *    IEEE      0, 30       100000      3.0e-34     2.7e-35
 *
 */

/* Copyright 2001 by Stephen L. Moshier (moshier@na-net.ornl.gov).

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

#include <math.h>
#include <math_private.h>
#include <float.h>

/* 1 / sqrt(pi) */
static const long double ONEOSQPI = 5.6418958354775628694807945156077258584405E-1L;
/* 2 / pi */
static const long double TWOOPI = 6.3661977236758134307553505349005744813784E-1L;
static const long double zero = 0.0L;

/* J0(x) = 1 - x^2/4 + x^2 x^2 R(x^2)
   Peak relative error 3.4e-37
   0 <= x <= 2  */
#define NJ0_2N 6
static const long double J0_2N[NJ0_2N + 1] = {
  3.133239376997663645548490085151484674892E16L,
 -5.479944965767990821079467311839107722107E14L,
  6.290828903904724265980249871997551894090E12L,
 -3.633750176832769659849028554429106299915E10L,
  1.207743757532429576399485415069244807022E8L,
 -2.107485999925074577174305650549367415465E5L,
  1.562826808020631846245296572935547005859E2L,
};
#define NJ0_2D 6
static const long double J0_2D[NJ0_2D + 1] = {
  2.005273201278504733151033654496928968261E18L,
  2.063038558793221244373123294054149790864E16L,
  1.053350447931127971406896594022010524994E14L,
  3.496556557558702583143527876385508882310E11L,
  8.249114511878616075860654484367133976306E8L,
  1.402965782449571800199759247964242790589E6L,
  1.619910762853439600957801751815074787351E3L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2),
   0 <= 1/x <= .0625
   Peak relative error 3.3e-36  */
#define NP16_IN 9
static const long double P16_IN[NP16_IN + 1] = {
  -1.901689868258117463979611259731176301065E-16L,
  -1.798743043824071514483008340803573980931E-13L,
  -6.481746687115262291873324132944647438959E-11L,
  -1.150651553745409037257197798528294248012E-8L,
  -1.088408467297401082271185599507222695995E-6L,
  -5.551996725183495852661022587879817546508E-5L,
  -1.477286941214245433866838787454880214736E-3L,
  -1.882877976157714592017345347609200402472E-2L,
  -9.620983176855405325086530374317855880515E-2L,
  -1.271468546258855781530458854476627766233E-1L,
};
#define NP16_ID 9
static const long double P16_ID[NP16_ID + 1] = {
  2.704625590411544837659891569420764475007E-15L,
  2.562526347676857624104306349421985403573E-12L,
  9.259137589952741054108665570122085036246E-10L,
  1.651044705794378365237454962653430805272E-7L,
  1.573561544138733044977714063100859136660E-5L,
  8.134482112334882274688298469629884804056E-4L,
  2.219259239404080863919375103673593571689E-2L,
  2.976990606226596289580242451096393862792E-1L,
  1.713895630454693931742734911930937246254E0L,
  3.231552290717904041465898249160757368855E0L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
    0.0625 <= 1/x <= 0.125
    Peak relative error 2.4e-35  */
#define NP8_16N 10
static const long double P8_16N[NP8_16N + 1] = {
  -2.335166846111159458466553806683579003632E-15L,
  -1.382763674252402720401020004169367089975E-12L,
  -3.192160804534716696058987967592784857907E-10L,
  -3.744199606283752333686144670572632116899E-8L,
  -2.439161236879511162078619292571922772224E-6L,
  -9.068436986859420951664151060267045346549E-5L,
  -1.905407090637058116299757292660002697359E-3L,
  -2.164456143936718388053842376884252978872E-2L,
  -1.212178415116411222341491717748696499966E-1L,
  -2.782433626588541494473277445959593334494E-1L,
  -1.670703190068873186016102289227646035035E-1L,
};
#define NP8_16D 10
static const long double P8_16D[NP8_16D + 1] = {
  3.321126181135871232648331450082662856743E-14L,
  1.971894594837650840586859228510007703641E-11L,
  4.571144364787008285981633719513897281690E-9L,
  5.396419143536287457142904742849052402103E-7L,
  3.551548222385845912370226756036899901549E-5L,
  1.342353874566932014705609788054598013516E-3L,
  2.899133293006771317589357444614157734385E-2L,
  3.455374978185770197704507681491574261545E-1L,
  2.116616964297512311314454834712634820514E0L,
  5.850768316827915470087758636881584174432E0L,
  5.655273858938766830855753983631132928968E0L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
  0.125 <= 1/x <= 0.1875
  Peak relative error 2.7e-35  */
#define NP5_8N 10
static const long double P5_8N[NP5_8N + 1] = {
  -1.270478335089770355749591358934012019596E-12L,
  -4.007588712145412921057254992155810347245E-10L,
  -4.815187822989597568124520080486652009281E-8L,
  -2.867070063972764880024598300408284868021E-6L,
  -9.218742195161302204046454768106063638006E-5L,
  -1.635746821447052827526320629828043529997E-3L,
  -1.570376886640308408247709616497261011707E-2L,
  -7.656484795303305596941813361786219477807E-2L,
  -1.659371030767513274944805479908858628053E-1L,
  -1.185340550030955660015841796219919804915E-1L,
  -8.920026499909994671248893388013790366712E-3L,
};
#define NP5_8D 9
static const long double P5_8D[NP5_8D + 1] = {
  1.806902521016705225778045904631543990314E-11L,
  5.728502760243502431663549179135868966031E-9L,
  6.938168504826004255287618819550667978450E-7L,
  4.183769964807453250763325026573037785902E-5L,
  1.372660678476925468014882230851637878587E-3L,
  2.516452105242920335873286419212708961771E-2L,
  2.550502712902647803796267951846557316182E-1L,
  1.365861559418983216913629123778747617072E0L,
  3.523825618308783966723472468855042541407E0L,
  3.656365803506136165615111349150536282434E0L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
   Peak relative error 3.5e-35
   0.1875 <= 1/x <= 0.25  */
#define NP4_5N 9
static const long double P4_5N[NP4_5N + 1] = {
  -9.791405771694098960254468859195175708252E-10L,
  -1.917193059944531970421626610188102836352E-7L,
  -1.393597539508855262243816152893982002084E-5L,
  -4.881863490846771259880606911667479860077E-4L,
  -8.946571245022470127331892085881699269853E-3L,
  -8.707474232568097513415336886103899434251E-2L,
  -4.362042697474650737898551272505525973766E-1L,
  -1.032712171267523975431451359962375617386E0L,
  -9.630502683169895107062182070514713702346E-1L,
  -2.251804386252969656586810309252357233320E-1L,
};
#define NP4_5D 9
static const long double P4_5D[NP4_5D + 1] = {
  1.392555487577717669739688337895791213139E-8L,
  2.748886559120659027172816051276451376854E-6L,
  2.024717710644378047477189849678576659290E-4L,
  7.244868609350416002930624752604670292469E-3L,
  1.373631762292244371102989739300382152416E-1L,
  1.412298581400224267910294815260613240668E0L,
  7.742495637843445079276397723849017617210E0L,
  2.138429269198406512028307045259503811861E1L,
  2.651547684548423476506826951831712762610E1L,
  1.167499382465291931571685222882909166935E1L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
   Peak relative error 2.3e-36
   0.25 <= 1/x <= 0.3125  */
#define NP3r2_4N 9
static const long double P3r2_4N[NP3r2_4N + 1] = {
  -2.589155123706348361249809342508270121788E-8L,
  -3.746254369796115441118148490849195516593E-6L,
  -1.985595497390808544622893738135529701062E-4L,
  -5.008253705202932091290132760394976551426E-3L,
  -6.529469780539591572179155511840853077232E-2L,
  -4.468736064761814602927408833818990271514E-1L,
  -1.556391252586395038089729428444444823380E0L,
  -2.533135309840530224072920725976994981638E0L,
  -1.605509621731068453869408718565392869560E0L,
  -2.518966692256192789269859830255724429375E-1L,
};
#define NP3r2_4D 9
static const long double P3r2_4D[NP3r2_4D + 1] = {
  3.682353957237979993646169732962573930237E-7L,
  5.386741661883067824698973455566332102029E-5L,
  2.906881154171822780345134853794241037053E-3L,
  7.545832595801289519475806339863492074126E-2L,
  1.029405357245594877344360389469584526654E0L,
  7.565706120589873131187989560509757626725E0L,
  2.951172890699569545357692207898667665796E1L,
  5.785723537170311456298467310529815457536E1L,
  5.095621464598267889126015412522773474467E1L,
  1.602958484169953109437547474953308401442E1L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
   Peak relative error 1.0e-35
   0.3125 <= 1/x <= 0.375  */
#define NP2r7_3r2N 9
static const long double P2r7_3r2N[NP2r7_3r2N + 1] = {
  -1.917322340814391131073820537027234322550E-7L,
  -1.966595744473227183846019639723259011906E-5L,
  -7.177081163619679403212623526632690465290E-4L,
  -1.206467373860974695661544653741899755695E-2L,
  -1.008656452188539812154551482286328107316E-1L,
  -4.216016116408810856620947307438823892707E-1L,
  -8.378631013025721741744285026537009814161E-1L,
  -6.973895635309960850033762745957946272579E-1L,
  -1.797864718878320770670740413285763554812E-1L,
  -4.098025357743657347681137871388402849581E-3L,
};
#define NP2r7_3r2D 8
static const long double P2r7_3r2D[NP2r7_3r2D + 1] = {
  2.726858489303036441686496086962545034018E-6L,
  2.840430827557109238386808968234848081424E-4L,
  1.063826772041781947891481054529454088832E-2L,
  1.864775537138364773178044431045514405468E-1L,
  1.665660052857205170440952607701728254211E0L,
  7.723745889544331153080842168958348568395E0L,
  1.810726427571829798856428548102077799835E1L,
  1.986460672157794440666187503833545388527E1L,
  8.645503204552282306364296517220055815488E0L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
   Peak relative error 1.3e-36
   0.3125 <= 1/x <= 0.4375  */
#define NP2r3_2r7N 9
static const long double P2r3_2r7N[NP2r3_2r7N + 1] = {
  -1.594642785584856746358609622003310312622E-6L,
  -1.323238196302221554194031733595194539794E-4L,
  -3.856087818696874802689922536987100372345E-3L,
  -5.113241710697777193011470733601522047399E-2L,
  -3.334229537209911914449990372942022350558E-1L,
  -1.075703518198127096179198549659283422832E0L,
  -1.634174803414062725476343124267110981807E0L,
  -1.030133247434119595616826842367268304880E0L,
  -1.989811539080358501229347481000707289391E-1L,
  -3.246859189246653459359775001466924610236E-3L,
};
#define NP2r3_2r7D 8
static const long double P2r3_2r7D[NP2r3_2r7D + 1] = {
  2.267936634217251403663034189684284173018E-5L,
  1.918112982168673386858072491437971732237E-3L,
  5.771704085468423159125856786653868219522E-2L,
  8.056124451167969333717642810661498890507E-1L,
  5.687897967531010276788680634413789328776E0L,
  2.072596760717695491085444438270778394421E1L,
  3.801722099819929988585197088613160496684E1L,
  3.254620235902912339534998592085115836829E1L,
  1.104847772130720331801884344645060675036E1L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* J0(x)cosX + Y0(x)sinX = sqrt( 2/(pi x)) P0(x), P0(x) = 1 + 1/x^2 R(1/x^2)
   Peak relative error 1.2e-35
   0.4375 <= 1/x <= 0.5  */
#define NP2_2r3N 8
static const long double P2_2r3N[NP2_2r3N + 1] = {
  -1.001042324337684297465071506097365389123E-4L,
  -6.289034524673365824853547252689991418981E-3L,
  -1.346527918018624234373664526930736205806E-1L,
  -1.268808313614288355444506172560463315102E0L,
  -5.654126123607146048354132115649177406163E0L,
  -1.186649511267312652171775803270911971693E1L,
  -1.094032424931998612551588246779200724257E1L,
  -3.728792136814520055025256353193674625267E0L,
  -3.000348318524471807839934764596331810608E-1L,
};
#define NP2_2r3D 8
static const long double P2_2r3D[NP2_2r3D + 1] = {
  1.423705538269770974803901422532055612980E-3L,
  9.171476630091439978533535167485230575894E-2L,
  2.049776318166637248868444600215942828537E0L,
  2.068970329743769804547326701946144899583E1L,
  1.025103500560831035592731539565060347709E2L,
  2.528088049697570728252145557167066708284E2L,
  2.992160327587558573740271294804830114205E2L,
  1.540193761146551025832707739468679973036E2L,
  2.779516701986912132637672140709452502650E1L,
  /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 2.2e-35
   0 <= 1/x <= .0625  */
#define NQ16_IN 10
static const long double Q16_IN[NQ16_IN + 1] = {
  2.343640834407975740545326632205999437469E-18L,
  2.667978112927811452221176781536278257448E-15L,
  1.178415018484555397390098879501969116536E-12L,
  2.622049767502719728905924701288614016597E-10L,
  3.196908059607618864801313380896308968673E-8L,
  2.179466154171673958770030655199434798494E-6L,
  8.139959091628545225221976413795645177291E-5L,
  1.563900725721039825236927137885747138654E-3L,
  1.355172364265825167113562519307194840307E-2L,
  3.928058355906967977269780046844768588532E-2L,
  1.107891967702173292405380993183694932208E-2L,
};
#define NQ16_ID 9
static const long double Q16_ID[NQ16_ID + 1] = {
  3.199850952578356211091219295199301766718E-17L,
  3.652601488020654842194486058637953363918E-14L,
  1.620179741394865258354608590461839031281E-11L,
  3.629359209474609630056463248923684371426E-9L,
  4.473680923894354600193264347733477363305E-7L,
  3.106368086644715743265603656011050476736E-5L,
  1.198239259946770604954664925153424252622E-3L,
  2.446041004004283102372887804475767568272E-2L,
  2.403235525011860603014707768815113698768E-1L,
  9.491006790682158612266270665136910927149E-1L,
 /* 1.000000000000000000000000000000000000000E0 */
 };

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 5.1e-36
   0.0625 <= 1/x <= 0.125  */
#define NQ8_16N 11
static const long double Q8_16N[NQ8_16N + 1] = {
  1.001954266485599464105669390693597125904E-17L,
  7.545499865295034556206475956620160007849E-15L,
  2.267838684785673931024792538193202559922E-12L,
  3.561909705814420373609574999542459912419E-10L,
  3.216201422768092505214730633842924944671E-8L,
  1.731194793857907454569364622452058554314E-6L,
  5.576944613034537050396518509871004586039E-5L,
  1.051787760316848982655967052985391418146E-3L,
  1.102852974036687441600678598019883746959E-2L,
  5.834647019292460494254225988766702933571E-2L,
  1.290281921604364618912425380717127576529E-1L,
  7.598886310387075708640370806458926458301E-2L,
};
#define NQ8_16D 11
static const long double Q8_16D[NQ8_16D + 1] = {
  1.368001558508338469503329967729951830843E-16L,
  1.034454121857542147020549303317348297289E-13L,
  3.128109209247090744354764050629381674436E-11L,
  4.957795214328501986562102573522064468671E-9L,
  4.537872468606711261992676606899273588899E-7L,
  2.493639207101727713192687060517509774182E-5L,
  8.294957278145328349785532236663051405805E-4L,
  1.646471258966713577374948205279380115839E-2L,
  1.878910092770966718491814497982191447073E-1L,
  1.152641605706170353727903052525652504075E0L,
  3.383550240669773485412333679367792932235E0L,
  3.823875252882035706910024716609908473970E0L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 3.9e-35
   0.125 <= 1/x <= 0.1875  */
#define NQ5_8N 10
static const long double Q5_8N[NQ5_8N + 1] = {
  1.750399094021293722243426623211733898747E-13L,
  6.483426211748008735242909236490115050294E-11L,
  9.279430665656575457141747875716899958373E-9L,
  6.696634968526907231258534757736576340266E-7L,
  2.666560823798895649685231292142838188061E-5L,
  6.025087697259436271271562769707550594540E-4L,
  7.652807734168613251901945778921336353485E-3L,
  5.226269002589406461622551452343519078905E-2L,
  1.748390159751117658969324896330142895079E-1L,
  2.378188719097006494782174902213083589660E-1L,
  8.383984859679804095463699702165659216831E-2L,
};
#define NQ5_8D 10
static const long double Q5_8D[NQ5_8D + 1] = {
  2.389878229704327939008104855942987615715E-12L,
  8.926142817142546018703814194987786425099E-10L,
  1.294065862406745901206588525833274399038E-7L,
  9.524139899457666250828752185212769682191E-6L,
  3.908332488377770886091936221573123353489E-4L,
  9.250427033957236609624199884089916836748E-3L,
  1.263420066165922645975830877751588421451E-1L,
  9.692527053860420229711317379861733180654E-1L,
  3.937813834630430172221329298841520707954E0L,
  7.603126427436356534498908111445191312181E0L,
  5.670677653334105479259958485084550934305E0L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 3.2e-35
   0.1875 <= 1/x <= 0.25  */
#define NQ4_5N 10
static const long double Q4_5N[NQ4_5N + 1] = {
  2.233870042925895644234072357400122854086E-11L,
  5.146223225761993222808463878999151699792E-9L,
  4.459114531468296461688753521109797474523E-7L,
  1.891397692931537975547242165291668056276E-5L,
  4.279519145911541776938964806470674565504E-4L,
  5.275239415656560634702073291768904783989E-3L,
  3.468698403240744801278238473898432608887E-2L,
  1.138773146337708415188856882915457888274E-1L,
  1.622717518946443013587108598334636458955E-1L,
  7.249040006390586123760992346453034628227E-2L,
  1.941595365256460232175236758506411486667E-3L,
};
#define NQ4_5D 9
static const long double Q4_5D[NQ4_5D + 1] = {
  3.049977232266999249626430127217988047453E-10L,
  7.120883230531035857746096928889676144099E-8L,
  6.301786064753734446784637919554359588859E-6L,
  2.762010530095069598480766869426308077192E-4L,
  6.572163250572867859316828886203406361251E-3L,
  8.752566114841221958200215255461843397776E-2L,
  6.487654992874805093499285311075289932664E-1L,
  2.576550017826654579451615283022812801435E0L,
  5.056392229924022835364779562707348096036E0L,
  4.179770081068251464907531367859072157773E0L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 1.4e-36
   0.25 <= 1/x <= 0.3125  */
#define NQ3r2_4N 10
static const long double Q3r2_4N[NQ3r2_4N + 1] = {
  6.126167301024815034423262653066023684411E-10L,
  1.043969327113173261820028225053598975128E-7L,
  6.592927270288697027757438170153763220190E-6L,
  2.009103660938497963095652951912071336730E-4L,
  3.220543385492643525985862356352195896964E-3L,
  2.774405975730545157543417650436941650990E-2L,
  1.258114008023826384487378016636555041129E-1L,
  2.811724258266902502344701449984698323860E-1L,
  2.691837665193548059322831687432415014067E-1L,
  7.949087384900985370683770525312735605034E-2L,
  1.229509543620976530030153018986910810747E-3L,
};
#define NQ3r2_4D 9
static const long double Q3r2_4D[NQ3r2_4D + 1] = {
  8.364260446128475461539941389210166156568E-9L,
  1.451301850638956578622154585560759862764E-6L,
  9.431830010924603664244578867057141839463E-5L,
  3.004105101667433434196388593004526182741E-3L,
  5.148157397848271739710011717102773780221E-2L,
  4.901089301726939576055285374953887874895E-1L,
  2.581760991981709901216967665934142240346E0L,
  7.257105880775059281391729708630912791847E0L,
  1.006014717326362868007913423810737369312E1L,
  5.879416600465399514404064187445293212470E0L,
 /* 1.000000000000000000000000000000000000000E0*/
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 3.8e-36
   0.3125 <= 1/x <= 0.375  */
#define NQ2r7_3r2N 9
static const long double Q2r7_3r2N[NQ2r7_3r2N + 1] = {
  7.584861620402450302063691901886141875454E-8L,
  9.300939338814216296064659459966041794591E-6L,
  4.112108906197521696032158235392604947895E-4L,
  8.515168851578898791897038357239630654431E-3L,
  8.971286321017307400142720556749573229058E-2L,
  4.885856732902956303343015636331874194498E-1L,
  1.334506268733103291656253500506406045846E0L,
  1.681207956863028164179042145803851824654E0L,
  8.165042692571721959157677701625853772271E-1L,
  9.805848115375053300608712721986235900715E-2L,
};
#define NQ2r7_3r2D 9
static const long double Q2r7_3r2D[NQ2r7_3r2D + 1] = {
  1.035586492113036586458163971239438078160E-6L,
  1.301999337731768381683593636500979713689E-4L,
  5.993695702564527062553071126719088859654E-3L,
  1.321184892887881883489141186815457808785E-1L,
  1.528766555485015021144963194165165083312E0L,
  9.561463309176490874525827051566494939295E0L,
  3.203719484883967351729513662089163356911E1L,
  5.497294687660930446641539152123568668447E1L,
  4.391158169390578768508675452986948391118E1L,
  1.347836630730048077907818943625789418378E1L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 2.2e-35
   0.375 <= 1/x <= 0.4375  */
#define NQ2r3_2r7N 9
static const long double Q2r3_2r7N[NQ2r3_2r7N + 1] = {
  4.455027774980750211349941766420190722088E-7L,
  4.031998274578520170631601850866780366466E-5L,
  1.273987274325947007856695677491340636339E-3L,
  1.818754543377448509897226554179659122873E-2L,
  1.266748858326568264126353051352269875352E-1L,
  4.327578594728723821137731555139472880414E-1L,
  6.892532471436503074928194969154192615359E-1L,
  4.490775818438716873422163588640262036506E-1L,
  8.649615949297322440032000346117031581572E-2L,
  7.261345286655345047417257611469066147561E-4L,
};
#define NQ2r3_2r7D 8
static const long double Q2r3_2r7D[NQ2r3_2r7D + 1] = {
  6.082600739680555266312417978064954793142E-6L,
  5.693622538165494742945717226571441747567E-4L,
  1.901625907009092204458328768129666975975E-2L,
  2.958689532697857335456896889409923371570E-1L,
  2.343124711045660081603809437993368799568E0L,
  9.665894032187458293568704885528192804376E0L,
  2.035273104990617136065743426322454881353E1L,
  2.044102010478792896815088858740075165531E1L,
  8.445937177863155827844146643468706599304E0L,
 /* 1.000000000000000000000000000000000000000E0 */
};

/* Y0(x)cosX - J0(x)sinX = sqrt( 2/(pi x)) Q0(x),
   Q0(x) = 1/x (-.125 + 1/x^2 R(1/x^2))
   Peak relative error 3.1e-36
   0.4375 <= 1/x <= 0.5  */
#define NQ2_2r3N 9
static const long double Q2_2r3N[NQ2_2r3N + 1] = {
  2.817566786579768804844367382809101929314E-6L,
  2.122772176396691634147024348373539744935E-4L,
  5.501378031780457828919593905395747517585E-3L,
  6.355374424341762686099147452020466524659E-2L,
  3.539652320122661637429658698954748337223E-1L,
  9.571721066119617436343740541777014319695E-1L,
  1.196258777828426399432550698612171955305E0L,
  6.069388659458926158392384709893753793967E-1L,
  9.026746127269713176512359976978248763621E-2L,
  5.317668723070450235320878117210807236375E-4L,
};
#define NQ2_2r3D 8
static const long double Q2_2r3D[NQ2_2r3D + 1] = {
  3.846924354014260866793741072933159380158E-5L,
  3.017562820057704325510067178327449946763E-3L,
  8.356305620686867949798885808540444210935E-2L,
  1.068314930499906838814019619594424586273E0L,
  6.900279623894821067017966573640732685233E0L,
  2.307667390886377924509090271780839563141E1L,
  3.921043465412723970791036825401273528513E1L,
  3.167569478939719383241775717095729233436E1L,
  1.051023841699200920276198346301543665909E1L,
 /* 1.000000000000000000000000000000000000000E0*/
};


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


/* Bessel function of the first kind, order zero.  */

long double
__ieee754_j0l (long double x)
{
  long double xx, xinv, z, p, q, c, s, cc, ss;

  if (! isfinite (x))
    {
      if (x != x)
	return x;
      else
	return 0.0L;
    }
  if (x == 0.0L)
    return 1.0L;

  xx = fabsl (x);
  if (xx <= 2.0L)
    {
      if (xx < 0x1p-57L)
	return 1.0L;
      /* 0 <= x <= 2 */
      z = xx * xx;
      p = z * z * neval (z, J0_2N, NJ0_2N) / deval (z, J0_2D, NJ0_2D);
      p -= 0.25L * z;
      p += 1.0L;
      return p;
    }

  /* X = x - pi/4
     cos(X) = cos(x) cos(pi/4) + sin(x) sin(pi/4)
     = 1/sqrt(2) * (cos(x) + sin(x))
     sin(X) = sin(x) cos(pi/4) - cos(x) sin(pi/4)
     = 1/sqrt(2) * (sin(x) - cos(x))
     sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
     cf. Fdlibm.  */
  __sincosl (xx, &s, &c);
  ss = s - c;
  cc = s + c;
  if (xx <= LDBL_MAX / 2.0L)
    {
      z = -__cosl (xx + xx);
      if ((s * c) < 0)
	cc = z / ss;
      else
	ss = z / cc;
    }

  if (xx > 0x1p256L)
    return ONEOSQPI * cc / __ieee754_sqrtl (xx);

  xinv = 1.0L / xx;
  z = xinv * xinv;
  if (xinv <= 0.25)
    {
      if (xinv <= 0.125)
	{
	  if (xinv <= 0.0625)
	    {
	      p = neval (z, P16_IN, NP16_IN) / deval (z, P16_ID, NP16_ID);
	      q = neval (z, Q16_IN, NQ16_IN) / deval (z, Q16_ID, NQ16_ID);
	    }
	  else
	    {
	      p = neval (z, P8_16N, NP8_16N) / deval (z, P8_16D, NP8_16D);
	      q = neval (z, Q8_16N, NQ8_16N) / deval (z, Q8_16D, NQ8_16D);
	    }
	}
      else if (xinv <= 0.1875)
	{
	  p = neval (z, P5_8N, NP5_8N) / deval (z, P5_8D, NP5_8D);
	  q = neval (z, Q5_8N, NQ5_8N) / deval (z, Q5_8D, NQ5_8D);
	}
      else
	{
	  p = neval (z, P4_5N, NP4_5N) / deval (z, P4_5D, NP4_5D);
	  q = neval (z, Q4_5N, NQ4_5N) / deval (z, Q4_5D, NQ4_5D);
	}
    }				/* .25 */
  else /* if (xinv <= 0.5) */
    {
      if (xinv <= 0.375)
	{
	  if (xinv <= 0.3125)
	    {
	      p = neval (z, P3r2_4N, NP3r2_4N) / deval (z, P3r2_4D, NP3r2_4D);
	      q = neval (z, Q3r2_4N, NQ3r2_4N) / deval (z, Q3r2_4D, NQ3r2_4D);
	    }
	  else
	    {
	      p = neval (z, P2r7_3r2N, NP2r7_3r2N)
		  / deval (z, P2r7_3r2D, NP2r7_3r2D);
	      q = neval (z, Q2r7_3r2N, NQ2r7_3r2N)
		  / deval (z, Q2r7_3r2D, NQ2r7_3r2D);
	    }
	}
      else if (xinv <= 0.4375)
	{
	  p = neval (z, P2r3_2r7N, NP2r3_2r7N)
	      / deval (z, P2r3_2r7D, NP2r3_2r7D);
	  q = neval (z, Q2r3_2r7N, NQ2r3_2r7N)
	      / deval (z, Q2r3_2r7D, NQ2r3_2r7D);
	}
      else
	{
	  p = neval (z, P2_2r3N, NP2_2r3N) / deval (z, P2_2r3D, NP2_2r3D);
	  q = neval (z, Q2_2r3N, NQ2_2r3N) / deval (z, Q2_2r3D, NQ2_2r3D);
	}
    }
  p = 1.0L + z * p;
  q = z * xinv * q;
  q = q - 0.125L * xinv;
  z = ONEOSQPI * (p * cc - q * ss) / __ieee754_sqrtl (xx);
  return z;
}
strong_alias (__ieee754_j0l, __j0l_finite)


/* Y0(x) = 2/pi * log(x) * J0(x) + R(x^2)
   Peak absolute error 1.7e-36 (relative where Y0 > 1)
   0 <= x <= 2   */
#define NY0_2N 7
static long double Y0_2N[NY0_2N + 1] = {
 -1.062023609591350692692296993537002558155E19L,
  2.542000883190248639104127452714966858866E19L,
 -1.984190771278515324281415820316054696545E18L,
  4.982586044371592942465373274440222033891E16L,
 -5.529326354780295177243773419090123407550E14L,
  3.013431465522152289279088265336861140391E12L,
 -7.959436160727126750732203098982718347785E9L,
  8.230845651379566339707130644134372793322E6L,
};
#define NY0_2D 7
static long double Y0_2D[NY0_2D + 1] = {
  1.438972634353286978700329883122253752192E20L,
  1.856409101981569254247700169486907405500E18L,
  1.219693352678218589553725579802986255614E16L,
  5.389428943282838648918475915779958097958E13L,
  1.774125762108874864433872173544743051653E11L,
  4.522104832545149534808218252434693007036E8L,
  8.872187401232943927082914504125234454930E5L,
  1.251945613186787532055610876304669413955E3L,
 /* 1.000000000000000000000000000000000000000E0 */
};

static const long double U0 = -7.3804295108687225274343927948483016310862e-02L;

/* Bessel function of the second kind, order zero.  */

long double
 __ieee754_y0l(long double x)
{
  long double xx, xinv, z, p, q, c, s, cc, ss;

  if (! isfinite (x))
    {
      if (x != x)
	return x;
      else
	return 0.0L;
    }
  if (x <= 0.0L)
    {
      if (x < 0.0L)
	return (zero / (zero * x));
      return -HUGE_VALL + x;
    }
  xx = fabsl (x);
  if (xx <= 0x1p-57)
    return U0 + TWOOPI * __ieee754_logl (x);
  if (xx <= 2.0L)
    {
      /* 0 <= x <= 2 */
      z = xx * xx;
      p = neval (z, Y0_2N, NY0_2N) / deval (z, Y0_2D, NY0_2D);
      p = TWOOPI * __ieee754_logl (x) * __ieee754_j0l (x) + p;
      return p;
    }

  /* X = x - pi/4
     cos(X) = cos(x) cos(pi/4) + sin(x) sin(pi/4)
     = 1/sqrt(2) * (cos(x) + sin(x))
     sin(X) = sin(x) cos(pi/4) - cos(x) sin(pi/4)
     = 1/sqrt(2) * (sin(x) - cos(x))
     sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
     cf. Fdlibm.  */
  __sincosl (x, &s, &c);
  ss = s - c;
  cc = s + c;
  if (xx <= LDBL_MAX / 2.0L)
    {
      z = -__cosl (x + x);
      if ((s * c) < 0)
	cc = z / ss;
      else
	ss = z / cc;
    }

  if (xx > 0x1p256L)
    return ONEOSQPI * ss / __ieee754_sqrtl (x);

  xinv = 1.0L / xx;
  z = xinv * xinv;
  if (xinv <= 0.25)
    {
      if (xinv <= 0.125)
	{
	  if (xinv <= 0.0625)
	    {
	      p = neval (z, P16_IN, NP16_IN) / deval (z, P16_ID, NP16_ID);
	      q = neval (z, Q16_IN, NQ16_IN) / deval (z, Q16_ID, NQ16_ID);
	    }
	  else
	    {
	      p = neval (z, P8_16N, NP8_16N) / deval (z, P8_16D, NP8_16D);
	      q = neval (z, Q8_16N, NQ8_16N) / deval (z, Q8_16D, NQ8_16D);
	    }
	}
      else if (xinv <= 0.1875)
	{
	  p = neval (z, P5_8N, NP5_8N) / deval (z, P5_8D, NP5_8D);
	  q = neval (z, Q5_8N, NQ5_8N) / deval (z, Q5_8D, NQ5_8D);
	}
      else
	{
	  p = neval (z, P4_5N, NP4_5N) / deval (z, P4_5D, NP4_5D);
	  q = neval (z, Q4_5N, NQ4_5N) / deval (z, Q4_5D, NQ4_5D);
	}
    }				/* .25 */
  else /* if (xinv <= 0.5) */
    {
      if (xinv <= 0.375)
	{
	  if (xinv <= 0.3125)
	    {
	      p = neval (z, P3r2_4N, NP3r2_4N) / deval (z, P3r2_4D, NP3r2_4D);
	      q = neval (z, Q3r2_4N, NQ3r2_4N) / deval (z, Q3r2_4D, NQ3r2_4D);
	    }
	  else
	    {
	      p = neval (z, P2r7_3r2N, NP2r7_3r2N)
		  / deval (z, P2r7_3r2D, NP2r7_3r2D);
	      q = neval (z, Q2r7_3r2N, NQ2r7_3r2N)
		  / deval (z, Q2r7_3r2D, NQ2r7_3r2D);
	    }
	}
      else if (xinv <= 0.4375)
	{
	  p = neval (z, P2r3_2r7N, NP2r3_2r7N)
	      / deval (z, P2r3_2r7D, NP2r3_2r7D);
	  q = neval (z, Q2r3_2r7N, NQ2r3_2r7N)
	      / deval (z, Q2r3_2r7D, NQ2r3_2r7D);
	}
      else
	{
	  p = neval (z, P2_2r3N, NP2_2r3N) / deval (z, P2_2r3D, NP2_2r3D);
	  q = neval (z, Q2_2r3N, NQ2_2r3N) / deval (z, Q2_2r3D, NQ2_2r3D);
	}
    }
  p = 1.0L + z * p;
  q = z * xinv * q;
  q = q - 0.125L * xinv;
  z = ONEOSQPI * (p * ss + q * cc) / __ieee754_sqrtl (x);
  return z;
}
strong_alias (__ieee754_y0l, __y0l_finite)
