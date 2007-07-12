#include "nldbl-compat.h"

int
attribute_hidden
sscanf (const char *s, const char *fmt, ...)
{
  va_list arg;
  int done;

  va_start (arg, fmt);
  done = __nldbl_vsscanf (s, fmt, arg);
  va_end (arg);

  return done;
}
extern __typeof (sscanf) _IO_sscanf attribute_hidden;
strong_alias (sscanf, _IO_sscanf)
