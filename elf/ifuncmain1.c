/* Test STT_GNU_IFUNC symbols:

   1. Direct function call.
   2. Function pointer.
   3. Visibility without override.
 */

#include <stdlib.h>

int ret_foo;
int ret_foo_hidden;
int ret_foo_protected;

extern int foo (void);
extern int foo_protected (void);

#ifndef FOO_P
typedef int (*foo_p) (void);
#endif

foo_p foo_ptr = foo;
foo_p foo_procted_ptr = foo_protected;

extern foo_p get_foo_p (void);
extern foo_p get_foo_hidden_p (void);
extern foo_p get_foo_protected_p (void);

int
main (void)
{
  foo_p p;
  
  if (foo_ptr != foo)
    abort ();
  if (foo () != -1)
    abort ();
  if ((*foo_ptr) () != -1)
    abort ();

  if (foo_procted_ptr != foo_protected)
    abort ();
  if (foo_protected () != 0)
    abort ();
  if ((*foo_procted_ptr) () != 0)
    abort ();

  p = get_foo_p ();
  if (p != foo)
    abort ();
  if (ret_foo != -1 || (*p) () != ret_foo)
    abort ();

  p = get_foo_hidden_p ();
  if (ret_foo_hidden != 1 || (*p) () != ret_foo_hidden)
    abort ();

  p = get_foo_protected_p ();
  if (p != foo_protected)
    abort ();
  if (ret_foo_protected != 0 || (*p) () != ret_foo_protected)
    abort ();

  return 0;
}
