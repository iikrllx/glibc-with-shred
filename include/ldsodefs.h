/* We must use the appropriate version for the system.  */
#ifdef __ELF__
# include <elf/ldsodefs.h>
#else
/* We have no dynamic loading.  Define the macros we need here as dummy
   versions.  */
# ifndef _LDSODEFS_H
# define _LDSODEFS_H	1

/* Call a function through a pointer.  */
# define _CALL_DL_FCT(fctp, args) (*fctp) args
# define CALL_DL_FCT(fctp, args) (*fctp) args

# endif	/* ldsodefs.h */
#endif
