/* Reset statistics.
   Copyright (C) 1999-2023 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "thread_dbP.h"


td_err_e
td_ta_reset_stats (const td_thragent_t *ta)
{
  /* XXX We have to figure out what has to be done.  */
  LOG ("td_ta_reset_stats");

  /* Test whether the TA parameter is ok.  */
  if (! ta_ok (ta))
    return TD_BADTA;

  return TD_OK;
}
