/* This file generated by gawk ../manual/errno.texi ../../mach/mach/message.h ../../mach/mach/kern_return.h ../../mach/mach/mig_errors.h ../../mach/device/device_types.h.  */

/* The Hurd uses Mach error system 0x10, currently only subsystem 0. */
#ifndef _HURD_ERRNO
#define _HURD_ERRNO(n)	((0x10 << 26) | ((n) & 0x3fff))
#endif

#ifdef _ERRNO_H

enum __error_t_codes
{
#undef EDOM
#undef ERANGE
	EPERM           = _HURD_ERRNO (1),
#define	EPERM           _HURD_ERRNO (1) /* Operation not permitted */
	ENOENT          = _HURD_ERRNO (2),
#define	ENOENT          _HURD_ERRNO (2) /* No such file or directory */
	ESRCH           = _HURD_ERRNO (3),
#define	ESRCH           _HURD_ERRNO (3) /* No such process */
	EINTR           = _HURD_ERRNO (4),
#define	EINTR           _HURD_ERRNO (4) /* Interrupted system call */
	EIO             = _HURD_ERRNO (5),
#define	EIO             _HURD_ERRNO (5) /* Input/output error */
	ENXIO           = _HURD_ERRNO (6),
#define	ENXIO           _HURD_ERRNO (6) /* Device not configured */
	E2BIG           = _HURD_ERRNO (7),
#define	E2BIG           _HURD_ERRNO (7) /* Argument list too long */
	ENOEXEC         = _HURD_ERRNO (8),
#define	ENOEXEC         _HURD_ERRNO (8) /* Exec format error */
	EBADF           = _HURD_ERRNO (9),
#define	EBADF           _HURD_ERRNO (9) /* Bad file descriptor */
	ECHILD          = _HURD_ERRNO (10),
#define	ECHILD          _HURD_ERRNO (10)/* No child processes */
	EDEADLK         = _HURD_ERRNO (11),
#define	EDEADLK         _HURD_ERRNO (11)/* Resource deadlock avoided */
	ENOMEM          = _HURD_ERRNO (12),
#define	ENOMEM          _HURD_ERRNO (12)/* Cannot allocate memory */
	EACCES          = _HURD_ERRNO (13),
#define	EACCES          _HURD_ERRNO (13)/* Permission denied */
	EFAULT          = _HURD_ERRNO (14),
#define	EFAULT          _HURD_ERRNO (14)/* Bad address */
	ENOTBLK         = _HURD_ERRNO (15),
#define	ENOTBLK         _HURD_ERRNO (15)/* Block device required */
	EBUSY           = _HURD_ERRNO (16),
#define	EBUSY           _HURD_ERRNO (16)/* Device busy */
	EEXIST          = _HURD_ERRNO (17),
#define	EEXIST          _HURD_ERRNO (17)/* File exists */
	EXDEV           = _HURD_ERRNO (18),
#define	EXDEV           _HURD_ERRNO (18)/* Invalid cross-device link */
	ENODEV          = _HURD_ERRNO (19),
#define	ENODEV          _HURD_ERRNO (19)/* Operation not supported by device */
	ENOTDIR         = _HURD_ERRNO (20),
#define	ENOTDIR         _HURD_ERRNO (20)/* Not a directory */
	EISDIR          = _HURD_ERRNO (21),
#define	EISDIR          _HURD_ERRNO (21)/* Is a directory */
	EINVAL          = _HURD_ERRNO (22),
#define	EINVAL          _HURD_ERRNO (22)/* Invalid argument */
	EMFILE          = _HURD_ERRNO (24),
#define	EMFILE          _HURD_ERRNO (24)/* Too many open files */
	ENFILE          = _HURD_ERRNO (23),
#define	ENFILE          _HURD_ERRNO (23)/* Too many open files in system */
	ENOTTY          = _HURD_ERRNO (25),
#define	ENOTTY          _HURD_ERRNO (25)/* Inappropriate ioctl for device */
	ETXTBSY         = _HURD_ERRNO (26),
#define	ETXTBSY         _HURD_ERRNO (26)/* Text file busy */
	EFBIG           = _HURD_ERRNO (27),
#define	EFBIG           _HURD_ERRNO (27)/* File too large */
	ENOSPC          = _HURD_ERRNO (28),
#define	ENOSPC          _HURD_ERRNO (28)/* No space left on device */
	ESPIPE          = _HURD_ERRNO (29),
#define	ESPIPE          _HURD_ERRNO (29)/* Illegal seek */
	EROFS           = _HURD_ERRNO (30),
#define	EROFS           _HURD_ERRNO (30)/* Read-only file system */
	EMLINK          = _HURD_ERRNO (31),
#define	EMLINK          _HURD_ERRNO (31)/* Too many links */
	EPIPE           = _HURD_ERRNO (32),
#define	EPIPE           _HURD_ERRNO (32)/* Broken pipe */
	EDOM            = _HURD_ERRNO (33),
#define	EDOM            _HURD_ERRNO (33)/* Numerical argument out of domain */
	ERANGE          = _HURD_ERRNO (34),
#define	ERANGE          _HURD_ERRNO (34)/* Numerical result out of range */
	EAGAIN          = _HURD_ERRNO (35),
#define	EAGAIN          _HURD_ERRNO (35)/* Resource temporarily unavailable */
#define EWOULDBLOCK EAGAIN /* Operation would block */
	EINPROGRESS     = _HURD_ERRNO (36),
#define	EINPROGRESS     _HURD_ERRNO (36)/* Operation now in progress */
	EALREADY        = _HURD_ERRNO (37),
#define	EALREADY        _HURD_ERRNO (37)/* Operation already in progress */
	ENOTSOCK        = _HURD_ERRNO (38),
#define	ENOTSOCK        _HURD_ERRNO (38)/* Socket operation on non-socket */
	EMSGSIZE        = _HURD_ERRNO (40),
#define	EMSGSIZE        _HURD_ERRNO (40)/* Message too long */
	EPROTOTYPE      = _HURD_ERRNO (41),
#define	EPROTOTYPE      _HURD_ERRNO (41)/* Protocol wrong type for socket */
	ENOPROTOOPT     = _HURD_ERRNO (42),
#define	ENOPROTOOPT     _HURD_ERRNO (42)/* Protocol not available */
	EPROTONOSUPPORT = _HURD_ERRNO (43),
#define	EPROTONOSUPPORT _HURD_ERRNO (43)/* Protocol not supported */
	ESOCKTNOSUPPORT = _HURD_ERRNO (44),
#define	ESOCKTNOSUPPORT _HURD_ERRNO (44)/* Socket type not supported */
	EOPNOTSUPP      = _HURD_ERRNO (45),
#define	EOPNOTSUPP      _HURD_ERRNO (45)/* Operation not supported */
	EPFNOSUPPORT    = _HURD_ERRNO (46),
#define	EPFNOSUPPORT    _HURD_ERRNO (46)/* Protocol family not supported */
	EAFNOSUPPORT    = _HURD_ERRNO (47),
#define	EAFNOSUPPORT    _HURD_ERRNO (47)/* Address family not supported by protocol family */
	EADDRINUSE      = _HURD_ERRNO (48),
#define	EADDRINUSE      _HURD_ERRNO (48)/* Address already in use */
	EADDRNOTAVAIL   = _HURD_ERRNO (49),
#define	EADDRNOTAVAIL   _HURD_ERRNO (49)/* Can't assign requested address */
	ENETDOWN        = _HURD_ERRNO (50),
#define	ENETDOWN        _HURD_ERRNO (50)/* Network is down */
	ENETUNREACH     = _HURD_ERRNO (51),
#define	ENETUNREACH     _HURD_ERRNO (51)/* Network is unreachable */
	ENETRESET       = _HURD_ERRNO (52),
#define	ENETRESET       _HURD_ERRNO (52)/* Network dropped connection on reset */
	ECONNABORTED    = _HURD_ERRNO (53),
#define	ECONNABORTED    _HURD_ERRNO (53)/* Software caused connection abort */
	ECONNRESET      = _HURD_ERRNO (54),
#define	ECONNRESET      _HURD_ERRNO (54)/* Connection reset by peer */
	ENOBUFS         = _HURD_ERRNO (55),
#define	ENOBUFS         _HURD_ERRNO (55)/* No buffer space available */
	EISCONN         = _HURD_ERRNO (56),
#define	EISCONN         _HURD_ERRNO (56)/* Socket is already connected */
	ENOTCONN        = _HURD_ERRNO (57),
#define	ENOTCONN        _HURD_ERRNO (57)/* Socket is not connected */
	EDESTADDRREQ    = _HURD_ERRNO (39),
#define	EDESTADDRREQ    _HURD_ERRNO (39)/* Destination address required */
	ESHUTDOWN       = _HURD_ERRNO (58),
#define	ESHUTDOWN       _HURD_ERRNO (58)/* Can't send after socket shutdown */
	ETOOMANYREFS    = _HURD_ERRNO (59),
#define	ETOOMANYREFS    _HURD_ERRNO (59)/* Too many references: can't splice */
	ETIMEDOUT       = _HURD_ERRNO (60),
#define	ETIMEDOUT       _HURD_ERRNO (60)/* Connection timed out */
	ECONNREFUSED    = _HURD_ERRNO (61),
#define	ECONNREFUSED    _HURD_ERRNO (61)/* Connection refused */
	ELOOP           = _HURD_ERRNO (62),
#define	ELOOP           _HURD_ERRNO (62)/* Too many levels of symbolic links */
	ENAMETOOLONG    = _HURD_ERRNO (63),
#define	ENAMETOOLONG    _HURD_ERRNO (63)/* File name too long */
	EHOSTDOWN       = _HURD_ERRNO (64),
#define	EHOSTDOWN       _HURD_ERRNO (64)/* Host is down */
	EHOSTUNREACH    = _HURD_ERRNO (65),
#define	EHOSTUNREACH    _HURD_ERRNO (65)/* No route to host */
	ENOTEMPTY       = _HURD_ERRNO (66),
#define	ENOTEMPTY       _HURD_ERRNO (66)/* Directory not empty */
	EPROCLIM        = _HURD_ERRNO (67),
#define	EPROCLIM        _HURD_ERRNO (67)/* Too many processes */
	EUSERS          = _HURD_ERRNO (68),
#define	EUSERS          _HURD_ERRNO (68)/* Too many users */
	EDQUOT          = _HURD_ERRNO (69),
#define	EDQUOT          _HURD_ERRNO (69)/* Disc quota exceeded */
	ESTALE          = _HURD_ERRNO (70),
#define	ESTALE          _HURD_ERRNO (70)/* Stale NFS file handle */
	EREMOTE         = _HURD_ERRNO (71),
#define	EREMOTE         _HURD_ERRNO (71)/* Too many levels of remote in path */
	EBADRPC         = _HURD_ERRNO (72),
#define	EBADRPC         _HURD_ERRNO (72)/* RPC struct is bad */
	ERPCMISMATCH    = _HURD_ERRNO (73),
#define	ERPCMISMATCH    _HURD_ERRNO (73)/* RPC version wrong */
	EPROGUNAVAIL    = _HURD_ERRNO (74),
#define	EPROGUNAVAIL    _HURD_ERRNO (74)/* RPC program not available */
	EPROGMISMATCH   = _HURD_ERRNO (75),
#define	EPROGMISMATCH   _HURD_ERRNO (75)/* RPC program version wrong */
	EPROCUNAVAIL    = _HURD_ERRNO (76),
#define	EPROCUNAVAIL    _HURD_ERRNO (76)/* RPC bad procedure for program */
	ENOLCK          = _HURD_ERRNO (77),
#define	ENOLCK          _HURD_ERRNO (77)/* No locks available */
	EFTYPE          = _HURD_ERRNO (79),
#define	EFTYPE          _HURD_ERRNO (79)/* Inappropriate file type or format */
	EAUTH           = _HURD_ERRNO (80),
#define	EAUTH           _HURD_ERRNO (80)/* Authentication error */
	ENEEDAUTH       = _HURD_ERRNO (81),
#define	ENEEDAUTH       _HURD_ERRNO (81)/* Need authenticator */
	ENOSYS          = _HURD_ERRNO (78),
#define	ENOSYS          _HURD_ERRNO (78)/* Function not implemented */
	EBACKGROUND     = _HURD_ERRNO (100),
#define	EBACKGROUND     _HURD_ERRNO (100)/* Inappropriate operation for background process */
	EDIED           = _HURD_ERRNO (101),
#define	EDIED           _HURD_ERRNO (101)/* Translator died */
	ED              = _HURD_ERRNO (102),
#define	ED              _HURD_ERRNO (102)/* ? */
	EGREGIOUS       = _HURD_ERRNO (103),
#define	EGREGIOUS       _HURD_ERRNO (103)/* You really blew it this time */
	EIEIO           = _HURD_ERRNO (104),
#define	EIEIO           _HURD_ERRNO (104)/* Computer bought the farm */
	EGRATUITOUS     = _HURD_ERRNO (105),
#define	EGRATUITOUS     _HURD_ERRNO (105)/* Gratuitous error */

	/* Errors from <mach/message.h>.  */
	EMACH_SEND_IN_PROGRESS          = 0x10000001,
	EMACH_SEND_INVALID_DATA         = 0x10000002,
	EMACH_SEND_INVALID_DEST         = 0x10000003,
	EMACH_SEND_TIMED_OUT            = 0x10000004,
	EMACH_SEND_WILL_NOTIFY          = 0x10000005,
	EMACH_SEND_NOTIFY_IN_PROGRESS   = 0x10000006,
	EMACH_SEND_INTERRUPTED          = 0x10000007,
	EMACH_SEND_MSG_TOO_SMALL        = 0x10000008,
	EMACH_SEND_INVALID_REPLY        = 0x10000009,
	EMACH_SEND_INVALID_RIGHT        = 0x1000000a,
	EMACH_SEND_INVALID_NOTIFY       = 0x1000000b,
	EMACH_SEND_INVALID_MEMORY       = 0x1000000c,
	EMACH_SEND_NO_BUFFER            = 0x1000000d,
	EMACH_SEND_NO_NOTIFY            = 0x1000000e,
	EMACH_SEND_INVALID_TYPE         = 0x1000000f,
	EMACH_SEND_INVALID_HEADER       = 0x10000010,
	EMACH_RCV_IN_PROGRESS           = 0x10004001,
	EMACH_RCV_INVALID_NAME          = 0x10004002,
	EMACH_RCV_TIMED_OUT             = 0x10004003,
	EMACH_RCV_TOO_LARGE             = 0x10004004,
	EMACH_RCV_INTERRUPTED           = 0x10004005,
	EMACH_RCV_PORT_CHANGED          = 0x10004006,
	EMACH_RCV_INVALID_NOTIFY        = 0x10004007,
	EMACH_RCV_INVALID_DATA          = 0x10004008,
	EMACH_RCV_PORT_DIED             = 0x10004009,
	EMACH_RCV_IN_SET                = 0x1000400a,
	EMACH_RCV_HEADER_ERROR          = 0x1000400b,
	EMACH_RCV_BODY_ERROR            = 0x1000400c,

	/* Errors from <mach/kern_return.h>.  */
	EKERN_INVALID_ADDRESS           = 1,
	EKERN_PROTECTION_FAILURE        = 2,
	EKERN_NO_SPACE                  = 3,
	EKERN_INVALID_ARGUMENT          = 4,
	EKERN_FAILURE                   = 5,
	EKERN_RESOURCE_SHORTAGE         = 6,
	EKERN_NOT_RECEIVER              = 7,
	EKERN_NO_ACCESS                 = 8,
	EKERN_MEMORY_FAILURE            = 9,
	EKERN_MEMORY_ERROR              = 10,
	EKERN_NOT_IN_SET                = 12,
	EKERN_NAME_EXISTS               = 13,
	EKERN_ABORTED                   = 14,
	EKERN_INVALID_NAME              = 15,
	EKERN_INVALID_TASK              = 16,
	EKERN_INVALID_RIGHT             = 17,
	EKERN_INVALID_VALUE             = 18,
	EKERN_UREFS_OVERFLOW            = 19,
	EKERN_INVALID_CAPABILITY        = 20,
	EKERN_RIGHT_EXISTS              = 21,
	EKERN_INVALID_HOST              = 22,
	EKERN_MEMORY_PRESENT            = 23,

	/* Errors from <mach/mig_errors.h>.  */
	EMIG_TYPE_ERROR         = -300, /* client type check failure */
	EMIG_REPLY_MISMATCH     = -301, /* wrong reply message ID */
	EMIG_REMOTE_ERROR       = -302, /* server detected error */
	EMIG_BAD_ID             = -303, /* bad request message ID */
	EMIG_BAD_ARGUMENTS      = -304, /* server type check failure */
	EMIG_NO_REPLY           = -305, /* no reply should be sent */
	EMIG_EXCEPTION          = -306, /* server raised exception */
	EMIG_ARRAY_TOO_LARGE    = -307, /* array not large enough */
	EMIG_SERVER_DIED        = -308, /* server died */
	EMIG_DESTROY_REQUEST    = -309, /* destroy request with no reply */

	/* Errors from <device/device_types.h>.  */
	ED_IO_ERROR             = 2500, /* hardware IO error */
	ED_WOULD_BLOCK          = 2501, /* would block, but D_NOWAIT set */
	ED_NO_SUCH_DEVICE       = 2502, /* no such device */
	ED_ALREADY_OPEN         = 2503, /* exclusive-use device already open */
	ED_DEVICE_DOWN          = 2504, /* device has been shut down */
	ED_INVALID_OPERATION    = 2505, /* bad operation for device */
	ED_INVALID_RECNUM       = 2506, /* invalid record (block) number */
	ED_INVALID_SIZE         = 2507, /* invalid IO size */
	ED_NO_MEMORY            = 2508, /* memory allocation failure */
	ED_READ_ONLY            = 2509, /* device cannot be written to */

};

#define	_HURD_ERRNOS	106

/* User-visible type of error codes.  It is ok to use `int' or
   `kern_return_t' for these, but with `error_t' the debugger prints
   symbolic values.  */
#ifdef __USE_GNU
typedef enum __error_t_codes error_t;
#define __error_t_defined	1
#endif

/* errno is a per-thread variable.  */
#include <hurd/threadvar.h>
#define errno	(*__hurd_errno_location ())

#endif /* <errno.h> included.  */

#if !defined (_ERRNO_H) && defined (__need_Emath)
#define	EDOM            _HURD_ERRNO (33)/* Numerical argument out of domain */
#define	ERANGE          _HURD_ERRNO (34)/* Numerical result out of range */
#endif /* <errno.h> not included and need math error codes.  */
