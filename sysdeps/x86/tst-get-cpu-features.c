/* Test case for __x86_get_cpu_features interface
   Copyright (C) 2015-2020 Free Software Foundation, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/platform/x86.h>
#include <support/check.h>

#define CHECK_CPU_FEATURE(name)		\
  {					\
    if (HAS_CPU_FEATURE (name))		\
      printf ("  " #name "\n");		\
  }

#define CHECK_CPU_FEATURE_USABLE(name)	\
  {					\
    if (CPU_FEATURE_USABLE(name))	\
      printf ("  " #name "\n");		\
  }

static const char * const cpu_kinds[] =
{
  "Unknown",
  "Intel",
  "AMD",
  "ZHAOXIN",
  "Other",
};

static int
do_test (void)
{
  const struct cpu_features *cpu_features = __x86_get_cpu_features (0);

  switch (cpu_features->basic.kind)
    {
    case arch_kind_intel:
    case arch_kind_amd:
    case arch_kind_zhaoxin:
    case arch_kind_other:
      printf ("Vendor: %s\n", cpu_kinds[cpu_features->basic.kind]);
      printf ("Family: 0x%x\n", cpu_features->basic.family);
      printf ("Model: 0x%x\n", cpu_features->basic.model);
      printf ("Stepping: 0x%x\n", cpu_features->basic.stepping);
      break;

    default:
      abort ();
    }

#ifdef __SSE2__
  TEST_VERIFY_EXIT (HAS_CPU_FEATURE (SSE2));
#endif

  printf ("CPU features:\n");
  CHECK_CPU_FEATURE (SSE3);
  CHECK_CPU_FEATURE (PCLMULQDQ);
  CHECK_CPU_FEATURE (DTES64);
  CHECK_CPU_FEATURE (MONITOR);
  CHECK_CPU_FEATURE (DS_CPL);
  CHECK_CPU_FEATURE (VMX);
  CHECK_CPU_FEATURE (SMX);
  CHECK_CPU_FEATURE (EIST);
  CHECK_CPU_FEATURE (TM2);
  CHECK_CPU_FEATURE (SSSE3);
  CHECK_CPU_FEATURE (CNXT_ID);
  CHECK_CPU_FEATURE (SDBG);
  CHECK_CPU_FEATURE (FMA);
  CHECK_CPU_FEATURE (CMPXCHG16B);
  CHECK_CPU_FEATURE (XTPRUPDCTRL);
  CHECK_CPU_FEATURE (PDCM);
  CHECK_CPU_FEATURE (PCID);
  CHECK_CPU_FEATURE (DCA);
  CHECK_CPU_FEATURE (SSE4_1);
  CHECK_CPU_FEATURE (SSE4_2);
  CHECK_CPU_FEATURE (X2APIC);
  CHECK_CPU_FEATURE (MOVBE);
  CHECK_CPU_FEATURE (POPCNT);
  CHECK_CPU_FEATURE (TSC_DEADLINE);
  CHECK_CPU_FEATURE (AES);
  CHECK_CPU_FEATURE (XSAVE);
  CHECK_CPU_FEATURE (OSXSAVE);
  CHECK_CPU_FEATURE (AVX);
  CHECK_CPU_FEATURE (F16C);
  CHECK_CPU_FEATURE (RDRAND);
  CHECK_CPU_FEATURE (FPU);
  CHECK_CPU_FEATURE (VME);
  CHECK_CPU_FEATURE (DE);
  CHECK_CPU_FEATURE (PSE);
  CHECK_CPU_FEATURE (TSC);
  CHECK_CPU_FEATURE (MSR);
  CHECK_CPU_FEATURE (PAE);
  CHECK_CPU_FEATURE (MCE);
  CHECK_CPU_FEATURE (CX8);
  CHECK_CPU_FEATURE (APIC);
  CHECK_CPU_FEATURE (SEP);
  CHECK_CPU_FEATURE (MTRR);
  CHECK_CPU_FEATURE (PGE);
  CHECK_CPU_FEATURE (MCA);
  CHECK_CPU_FEATURE (CMOV);
  CHECK_CPU_FEATURE (PAT);
  CHECK_CPU_FEATURE (PSE_36);
  CHECK_CPU_FEATURE (PSN);
  CHECK_CPU_FEATURE (CLFSH);
  CHECK_CPU_FEATURE (DS);
  CHECK_CPU_FEATURE (ACPI);
  CHECK_CPU_FEATURE (MMX);
  CHECK_CPU_FEATURE (FXSR);
  CHECK_CPU_FEATURE (SSE);
  CHECK_CPU_FEATURE (SSE2);
  CHECK_CPU_FEATURE (SS);
  CHECK_CPU_FEATURE (HTT);
  CHECK_CPU_FEATURE (TM);
  CHECK_CPU_FEATURE (PBE);
  CHECK_CPU_FEATURE (FSGSBASE);
  CHECK_CPU_FEATURE (TSC_ADJUST);
  CHECK_CPU_FEATURE (SGX);
  CHECK_CPU_FEATURE (BMI1);
  CHECK_CPU_FEATURE (HLE);
  CHECK_CPU_FEATURE (AVX2);
  CHECK_CPU_FEATURE (SMEP);
  CHECK_CPU_FEATURE (BMI2);
  CHECK_CPU_FEATURE (ERMS);
  CHECK_CPU_FEATURE (INVPCID);
  CHECK_CPU_FEATURE (RTM);
  CHECK_CPU_FEATURE (RDT_M);
  CHECK_CPU_FEATURE (DEPR_FPU_CS_DS);
  CHECK_CPU_FEATURE (MPX);
  CHECK_CPU_FEATURE (RDT_A);
  CHECK_CPU_FEATURE (AVX512F);
  CHECK_CPU_FEATURE (AVX512DQ);
  CHECK_CPU_FEATURE (RDSEED);
  CHECK_CPU_FEATURE (ADX);
  CHECK_CPU_FEATURE (SMAP);
  CHECK_CPU_FEATURE (AVX512_IFMA);
  CHECK_CPU_FEATURE (CLFLUSHOPT);
  CHECK_CPU_FEATURE (CLWB);
  CHECK_CPU_FEATURE (TRACE);
  CHECK_CPU_FEATURE (AVX512PF);
  CHECK_CPU_FEATURE (AVX512ER);
  CHECK_CPU_FEATURE (AVX512CD);
  CHECK_CPU_FEATURE (SHA);
  CHECK_CPU_FEATURE (AVX512BW);
  CHECK_CPU_FEATURE (AVX512VL);
  CHECK_CPU_FEATURE (PREFETCHWT1);
  CHECK_CPU_FEATURE (AVX512_VBMI);
  CHECK_CPU_FEATURE (UMIP);
  CHECK_CPU_FEATURE (PKU);
  CHECK_CPU_FEATURE (OSPKE);
  CHECK_CPU_FEATURE (WAITPKG);
  CHECK_CPU_FEATURE (AVX512_VBMI2);
  CHECK_CPU_FEATURE (SHSTK);
  CHECK_CPU_FEATURE (GFNI);
  CHECK_CPU_FEATURE (VAES);
  CHECK_CPU_FEATURE (VPCLMULQDQ);
  CHECK_CPU_FEATURE (AVX512_VNNI);
  CHECK_CPU_FEATURE (AVX512_BITALG);
  CHECK_CPU_FEATURE (AVX512_VPOPCNTDQ);
  CHECK_CPU_FEATURE (RDPID);
  CHECK_CPU_FEATURE (KL);
  CHECK_CPU_FEATURE (CLDEMOTE);
  CHECK_CPU_FEATURE (MOVDIRI);
  CHECK_CPU_FEATURE (MOVDIR64B);
  CHECK_CPU_FEATURE (ENQCMD);
  CHECK_CPU_FEATURE (SGX_LC);
  CHECK_CPU_FEATURE (PKS);
  CHECK_CPU_FEATURE (AVX512_4VNNIW);
  CHECK_CPU_FEATURE (AVX512_4FMAPS);
  CHECK_CPU_FEATURE (FSRM);
  CHECK_CPU_FEATURE (UINTR);
  CHECK_CPU_FEATURE (AVX512_VP2INTERSECT);
  CHECK_CPU_FEATURE (MD_CLEAR);
  CHECK_CPU_FEATURE (SERIALIZE);
  CHECK_CPU_FEATURE (HYBRID);
  CHECK_CPU_FEATURE (TSXLDTRK);
  CHECK_CPU_FEATURE (PCONFIG);
  CHECK_CPU_FEATURE (IBT);
  CHECK_CPU_FEATURE (AMX_BF16);
  CHECK_CPU_FEATURE (AVX512_FP16);
  CHECK_CPU_FEATURE (AMX_TILE);
  CHECK_CPU_FEATURE (AMX_INT8);
  CHECK_CPU_FEATURE (IBRS_IBPB);
  CHECK_CPU_FEATURE (STIBP);
  CHECK_CPU_FEATURE (L1D_FLUSH);
  CHECK_CPU_FEATURE (ARCH_CAPABILITIES);
  CHECK_CPU_FEATURE (CORE_CAPABILITIES);
  CHECK_CPU_FEATURE (SSBD);
  CHECK_CPU_FEATURE (LAHF64_SAHF64);
  CHECK_CPU_FEATURE (SVM);
  CHECK_CPU_FEATURE (LZCNT);
  CHECK_CPU_FEATURE (SSE4A);
  CHECK_CPU_FEATURE (PREFETCHW);
  CHECK_CPU_FEATURE (XOP);
  CHECK_CPU_FEATURE (LWP);
  CHECK_CPU_FEATURE (FMA4);
  CHECK_CPU_FEATURE (TBM);
  CHECK_CPU_FEATURE (SYSCALL_SYSRET);
  CHECK_CPU_FEATURE (NX);
  CHECK_CPU_FEATURE (PAGE1GB);
  CHECK_CPU_FEATURE (RDTSCP);
  CHECK_CPU_FEATURE (LM);
  CHECK_CPU_FEATURE (XSAVEOPT);
  CHECK_CPU_FEATURE (XSAVEC);
  CHECK_CPU_FEATURE (XGETBV_ECX_1);
  CHECK_CPU_FEATURE (XSAVES);
  CHECK_CPU_FEATURE (XFD);
  CHECK_CPU_FEATURE (INVARIANT_TSC);
  CHECK_CPU_FEATURE (WBNOINVD);
  CHECK_CPU_FEATURE (AVX_VNNI);
  CHECK_CPU_FEATURE (AVX512_BF16);
  CHECK_CPU_FEATURE (FZLRM);
  CHECK_CPU_FEATURE (FSRS);
  CHECK_CPU_FEATURE (FSRCS);
  CHECK_CPU_FEATURE (HRESET);
  CHECK_CPU_FEATURE (LAM);
  CHECK_CPU_FEATURE (AESKLE);
  CHECK_CPU_FEATURE (WIDE_KL);

  printf ("Usable CPU features:\n");
  CHECK_CPU_FEATURE_USABLE (SSE3);
  CHECK_CPU_FEATURE_USABLE (PCLMULQDQ);
  CHECK_CPU_FEATURE_USABLE (DTES64);
  CHECK_CPU_FEATURE_USABLE (MONITOR);
  CHECK_CPU_FEATURE_USABLE (DS_CPL);
  CHECK_CPU_FEATURE_USABLE (VMX);
  CHECK_CPU_FEATURE_USABLE (SMX);
  CHECK_CPU_FEATURE_USABLE (EIST);
  CHECK_CPU_FEATURE_USABLE (TM2);
  CHECK_CPU_FEATURE_USABLE (SSSE3);
  CHECK_CPU_FEATURE_USABLE (CNXT_ID);
  CHECK_CPU_FEATURE_USABLE (SDBG);
  CHECK_CPU_FEATURE_USABLE (FMA);
  CHECK_CPU_FEATURE_USABLE (CMPXCHG16B);
  CHECK_CPU_FEATURE_USABLE (XTPRUPDCTRL);
  CHECK_CPU_FEATURE_USABLE (PDCM);
  CHECK_CPU_FEATURE_USABLE (PCID);
  CHECK_CPU_FEATURE_USABLE (DCA);
  CHECK_CPU_FEATURE_USABLE (SSE4_1);
  CHECK_CPU_FEATURE_USABLE (SSE4_2);
  CHECK_CPU_FEATURE_USABLE (X2APIC);
  CHECK_CPU_FEATURE_USABLE (MOVBE);
  CHECK_CPU_FEATURE_USABLE (POPCNT);
  CHECK_CPU_FEATURE_USABLE (TSC_DEADLINE);
  CHECK_CPU_FEATURE_USABLE (AES);
  CHECK_CPU_FEATURE_USABLE (XSAVE);
  CHECK_CPU_FEATURE_USABLE (OSXSAVE);
  CHECK_CPU_FEATURE_USABLE (AVX);
  CHECK_CPU_FEATURE_USABLE (F16C);
  CHECK_CPU_FEATURE_USABLE (RDRAND);
  CHECK_CPU_FEATURE_USABLE (FPU);
  CHECK_CPU_FEATURE_USABLE (VME);
  CHECK_CPU_FEATURE_USABLE (DE);
  CHECK_CPU_FEATURE_USABLE (PSE);
  CHECK_CPU_FEATURE_USABLE (TSC);
  CHECK_CPU_FEATURE_USABLE (MSR);
  CHECK_CPU_FEATURE_USABLE (PAE);
  CHECK_CPU_FEATURE_USABLE (MCE);
  CHECK_CPU_FEATURE_USABLE (CX8);
  CHECK_CPU_FEATURE_USABLE (APIC);
  CHECK_CPU_FEATURE_USABLE (SEP);
  CHECK_CPU_FEATURE_USABLE (MTRR);
  CHECK_CPU_FEATURE_USABLE (PGE);
  CHECK_CPU_FEATURE_USABLE (MCA);
  CHECK_CPU_FEATURE_USABLE (CMOV);
  CHECK_CPU_FEATURE_USABLE (PAT);
  CHECK_CPU_FEATURE_USABLE (PSE_36);
  CHECK_CPU_FEATURE_USABLE (PSN);
  CHECK_CPU_FEATURE_USABLE (CLFSH);
  CHECK_CPU_FEATURE_USABLE (DS);
  CHECK_CPU_FEATURE_USABLE (ACPI);
  CHECK_CPU_FEATURE_USABLE (MMX);
  CHECK_CPU_FEATURE_USABLE (FXSR);
  CHECK_CPU_FEATURE_USABLE (SSE);
  CHECK_CPU_FEATURE_USABLE (SSE2);
  CHECK_CPU_FEATURE_USABLE (SS);
  CHECK_CPU_FEATURE_USABLE (HTT);
  CHECK_CPU_FEATURE_USABLE (TM);
  CHECK_CPU_FEATURE_USABLE (PBE);
  CHECK_CPU_FEATURE_USABLE (FSGSBASE);
  CHECK_CPU_FEATURE_USABLE (TSC_ADJUST);
  CHECK_CPU_FEATURE_USABLE (SGX);
  CHECK_CPU_FEATURE_USABLE (BMI1);
  CHECK_CPU_FEATURE_USABLE (HLE);
  CHECK_CPU_FEATURE_USABLE (AVX2);
  CHECK_CPU_FEATURE_USABLE (SMEP);
  CHECK_CPU_FEATURE_USABLE (BMI2);
  CHECK_CPU_FEATURE_USABLE (ERMS);
  CHECK_CPU_FEATURE_USABLE (INVPCID);
  CHECK_CPU_FEATURE_USABLE (RTM);
  CHECK_CPU_FEATURE_USABLE (RDT_M);
  CHECK_CPU_FEATURE_USABLE (DEPR_FPU_CS_DS);
  CHECK_CPU_FEATURE_USABLE (MPX);
  CHECK_CPU_FEATURE_USABLE (RDT_A);
  CHECK_CPU_FEATURE_USABLE (AVX512F);
  CHECK_CPU_FEATURE_USABLE (AVX512DQ);
  CHECK_CPU_FEATURE_USABLE (RDSEED);
  CHECK_CPU_FEATURE_USABLE (ADX);
  CHECK_CPU_FEATURE_USABLE (SMAP);
  CHECK_CPU_FEATURE_USABLE (AVX512_IFMA);
  CHECK_CPU_FEATURE_USABLE (CLFLUSHOPT);
  CHECK_CPU_FEATURE_USABLE (CLWB);
  CHECK_CPU_FEATURE_USABLE (TRACE);
  CHECK_CPU_FEATURE_USABLE (AVX512PF);
  CHECK_CPU_FEATURE_USABLE (AVX512ER);
  CHECK_CPU_FEATURE_USABLE (AVX512CD);
  CHECK_CPU_FEATURE_USABLE (SHA);
  CHECK_CPU_FEATURE_USABLE (AVX512BW);
  CHECK_CPU_FEATURE_USABLE (AVX512VL);
  CHECK_CPU_FEATURE_USABLE (PREFETCHWT1);
  CHECK_CPU_FEATURE_USABLE (AVX512_VBMI);
  CHECK_CPU_FEATURE_USABLE (UMIP);
  CHECK_CPU_FEATURE_USABLE (PKU);
  CHECK_CPU_FEATURE_USABLE (OSPKE);
  CHECK_CPU_FEATURE_USABLE (WAITPKG);
  CHECK_CPU_FEATURE_USABLE (AVX512_VBMI2);
  CHECK_CPU_FEATURE_USABLE (GFNI);
  CHECK_CPU_FEATURE_USABLE (VAES);
  CHECK_CPU_FEATURE_USABLE (VPCLMULQDQ);
  CHECK_CPU_FEATURE_USABLE (AVX512_VNNI);
  CHECK_CPU_FEATURE_USABLE (AVX512_BITALG);
  CHECK_CPU_FEATURE_USABLE (AVX512_VPOPCNTDQ);
  CHECK_CPU_FEATURE_USABLE (RDPID);
  CHECK_CPU_FEATURE_USABLE (KL);
  CHECK_CPU_FEATURE_USABLE (CLDEMOTE);
  CHECK_CPU_FEATURE_USABLE (MOVDIRI);
  CHECK_CPU_FEATURE_USABLE (MOVDIR64B);
  CHECK_CPU_FEATURE_USABLE (ENQCMD);
  CHECK_CPU_FEATURE_USABLE (SGX_LC);
  CHECK_CPU_FEATURE_USABLE (PKS);
  CHECK_CPU_FEATURE_USABLE (AVX512_4VNNIW);
  CHECK_CPU_FEATURE_USABLE (AVX512_4FMAPS);
  CHECK_CPU_FEATURE_USABLE (FSRM);
  CHECK_CPU_FEATURE_USABLE (AVX512_VP2INTERSECT);
  CHECK_CPU_FEATURE_USABLE (MD_CLEAR);
  CHECK_CPU_FEATURE_USABLE (SERIALIZE);
  CHECK_CPU_FEATURE_USABLE (HYBRID);
  CHECK_CPU_FEATURE_USABLE (TSXLDTRK);
  CHECK_CPU_FEATURE_USABLE (PCONFIG);
  CHECK_CPU_FEATURE_USABLE (AMX_BF16);
  CHECK_CPU_FEATURE_USABLE (AVX512_FP16);
  CHECK_CPU_FEATURE_USABLE (AMX_TILE);
  CHECK_CPU_FEATURE_USABLE (AMX_INT8);
  CHECK_CPU_FEATURE_USABLE (IBRS_IBPB);
  CHECK_CPU_FEATURE_USABLE (STIBP);
  CHECK_CPU_FEATURE_USABLE (L1D_FLUSH);
  CHECK_CPU_FEATURE_USABLE (ARCH_CAPABILITIES);
  CHECK_CPU_FEATURE_USABLE (CORE_CAPABILITIES);
  CHECK_CPU_FEATURE_USABLE (SSBD);
  CHECK_CPU_FEATURE_USABLE (LAHF64_SAHF64);
  CHECK_CPU_FEATURE_USABLE (SVM);
  CHECK_CPU_FEATURE_USABLE (LZCNT);
  CHECK_CPU_FEATURE_USABLE (SSE4A);
  CHECK_CPU_FEATURE_USABLE (PREFETCHW);
  CHECK_CPU_FEATURE_USABLE (XOP);
  CHECK_CPU_FEATURE_USABLE (LWP);
  CHECK_CPU_FEATURE_USABLE (FMA4);
  CHECK_CPU_FEATURE_USABLE (TBM);
  CHECK_CPU_FEATURE_USABLE (SYSCALL_SYSRET);
  CHECK_CPU_FEATURE_USABLE (NX);
  CHECK_CPU_FEATURE_USABLE (PAGE1GB);
  CHECK_CPU_FEATURE_USABLE (RDTSCP);
  CHECK_CPU_FEATURE_USABLE (LM);
  CHECK_CPU_FEATURE_USABLE (XSAVEOPT);
  CHECK_CPU_FEATURE_USABLE (XSAVEC);
  CHECK_CPU_FEATURE_USABLE (XGETBV_ECX_1);
  CHECK_CPU_FEATURE_USABLE (XSAVES);
  CHECK_CPU_FEATURE_USABLE (XFD);
  CHECK_CPU_FEATURE_USABLE (INVARIANT_TSC);
  CHECK_CPU_FEATURE_USABLE (WBNOINVD);
  CHECK_CPU_FEATURE_USABLE (AVX_VNNI);
  CHECK_CPU_FEATURE_USABLE (AVX512_BF16);
  CHECK_CPU_FEATURE_USABLE (FZLRM);
  CHECK_CPU_FEATURE_USABLE (FSRS);
  CHECK_CPU_FEATURE_USABLE (FSRCS);
  CHECK_CPU_FEATURE_USABLE (AESKLE);
  CHECK_CPU_FEATURE_USABLE (WIDE_KL);

  return 0;
}

#include <support/test-driver.c>
