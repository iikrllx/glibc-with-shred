#include "nldbl-compat.h"
#include <complex.h>

double _Complex
attribute_hidden
ctanl (double _Complex x)
{
  return ctan (x);
}
