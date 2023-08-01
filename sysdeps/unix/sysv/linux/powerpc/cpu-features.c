/* Initialize cpu feature data.  PowerPC version.
   Copyright (C) 2017-2023 Free Software Foundation, Inc.
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

#include <array_length.h>
#include <stdint.h>
#include <cpu-features.h>
#include <elf/dl-tunables.h>
#include <unistd.h>
#include <string.h>

static void
TUNABLE_CALLBACK (set_hwcaps) (tunable_val_t *valp)
{
  /* The current IFUNC selection is always using the most recent
     features which are available via AT_HWCAP or AT_HWCAP2.  But in
     some scenarios it is useful to adjust this selection.

     The environment variable:

     GLIBC_TUNABLES=glibc.cpu.hwcaps=-xxx,yyy,....

     Can be used to enable HWCAP/HWCAP2 feature yyy, disable HWCAP/HWCAP2
     feature xxx, where the feature name is case-sensitive and has to match
     the ones mentioned in the file{sysdeps/powerpc/dl-procinfo.c}. */

  /* Copy the features from dl_powerpc_cpu_features, which contains the
     features provided by AT_HWCAP and AT_HWCAP2.  */
  struct cpu_features *cpu_features = &GLRO(dl_powerpc_cpu_features);
  unsigned long int tcbv_hwcap = cpu_features->hwcap;
  unsigned long int tcbv_hwcap2 = cpu_features->hwcap2;
  const char *token = valp->strval;
  do
    {
      const char *token_end, *feature;
      bool disable;
      size_t token_len, i, feature_len, offset = 0;
      /* Find token separator or end of string.  */
      for (token_end = token; *token_end != ','; token_end++)
	if (*token_end == '\0')
	  break;

      /* Determine feature.  */
      token_len = token_end - token;
      if (*token == '-')
	{
	  disable = true;
	  feature = token + 1;
	  feature_len = token_len - 1;
	}
      else
	{
	  disable = false;
	  feature = token;
	  feature_len = token_len;
	}
      for (i = 0; i < array_length (hwcap_tunables); ++i)
	{
	  const char *hwcap_name = hwcap_names + offset;
	  size_t hwcap_name_len = strlen (hwcap_name);
	  /* Check the tunable name on the supported list.  */
	  if (hwcap_name_len == feature_len
	      && memcmp (feature, hwcap_name, feature_len) == 0)
	    {
	      /* Update the hwcap and hwcap2 bits.  */
	      if (disable)
		{
		  /* Id is 1 for hwcap2 tunable.  */
		  if (hwcap_tunables[i].id)
		    cpu_features->hwcap2 &= ~(hwcap_tunables[i].mask);
		  else
		    cpu_features->hwcap &= ~(hwcap_tunables[i].mask);
		}
	      else
		{
		  /* Enable the features and also check that no unsupported
		     features were enabled by user.  */
		  if (hwcap_tunables[i].id)
		    cpu_features->hwcap2 |= (tcbv_hwcap2 & hwcap_tunables[i].mask);
		  else
		    cpu_features->hwcap |= (tcbv_hwcap & hwcap_tunables[i].mask);
		}
	      break;
	    }
	  offset += hwcap_name_len + 1;
	}
	token += token_len;
	/* ... and skip token separator for next round.  */
	if (*token == ',')
	  token++;
    }
  while (*token != '\0');
}

static inline void
init_cpu_features (struct cpu_features *cpu_features, uint64_t hwcaps[])
{
  /* Fill the cpu_features with the supported hwcaps
     which are set by __tcb_parse_hwcap_and_convert_at_platform.  */
  cpu_features->hwcap = hwcaps[0];
  cpu_features->hwcap2 = hwcaps[1];
  /* Default is to use aligned memory access on optimized function unless
     tunables is enable, since for this case user can explicit disable
     unaligned optimizations.  */
  int32_t cached_memfunc = TUNABLE_GET (glibc, cpu, cached_memopt, int32_t,
					NULL);
  cpu_features->use_cached_memopt = (cached_memfunc > 0);
  TUNABLE_GET (glibc, cpu, hwcaps, tunable_val_t *,
	       TUNABLE_CALLBACK (set_hwcaps));
}
