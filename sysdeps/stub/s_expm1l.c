#include <math.h>
#include <stdio.h>

long double
__expm1l (long double x)
{
  fputs ("__expm1l not implemented\n", stderr);
  return 0.0;
}
weak_alias (__expm1l, expm1l)

stub_warning (expm1l)
