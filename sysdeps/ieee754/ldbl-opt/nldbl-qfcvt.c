#define qfcvt qfcvt_XXX
#include "nldbl-compat.h"
#undef qfcvt

char *
qfcvt (double val, int ndigit, int *__restrict decpt, int *__restrict sign)
{
  return fcvt (val, ndigit, decpt, sign);
}
