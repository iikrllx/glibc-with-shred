/* Statistics interface for the minimal malloc implementation.
   Copyright (C) 2016-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifndef TST_INTERPOSE_AUX_H
#define TST_INTERPOSE_AUX_H

#include <stddef.h>

/* Return the number of allocations performed.  */
size_t malloc_allocation_count (void);

/* Return the number of deallocations performed.  */
size_t malloc_deallocation_count (void);

#endif /* TST_INTERPOSE_AUX_H */
