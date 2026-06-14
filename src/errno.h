/*=============================================================================
 * errno.h - Standard Error Codes for System Calls
 * Implements POSIX-style error codes for robust error handling
 *============================================================================*/
#ifndef TINYOS_ERRNO_H
#define TINYOS_ERRNO_H

/*
 * POSIX-Compatible Error Codes
 *
 * These error codes are returned as NEGATIVE values from system calls.
 * For example, if a system call fails, it returns -EINVAL, not EINVAL.
 *
 * This allows system calls to return:
 *   - Positive values or zero for success
 *   - Negative values for errors
 *
 * User-space wrappers can then set errno = -return_value and return -1.
 */

/* Success (not an error) */
#define E_SUCCESS       0    /* Operation completed successfully */

/* Argument errors */
#define EPERM           1    /* Operation not permitted */
#define ENOENT          2    /* No such file or directory */
#define ESRCH           3    /* No such process */
#define EINTR           4    /* Interrupted system call */
#define EIO             5    /* I/O error */
#define ENXIO           6    /* No such device or address */
#define E2BIG           7    /* Argument list too long */
#define ENOEXEC         8    /* Exec format error */
#define EBADF           9    /* Bad file descriptor */
#define ECHILD          10   /* No child processes */
#define EAGAIN          11   /* Try again (also EWOULDBLOCK) */
#define ENOMEM          12   /* Out of memory */
#define EACCES          13   /* Permission denied */
#define EFAULT          14   /* Bad address (invalid pointer) */
#define ENOTBLK         15   /* Block device required */
#define EBUSY           16   /* Device or resource busy */
#define EEXIST          17   /* File exists */
#define EXDEV           18   /* Cross-device link */
#define ENODEV          19   /* No such device */
#define ENOTDIR         20   /* Not a directory */
#define EISDIR          21   /* Is a directory */
#define EINVAL          22   /* Invalid argument */
#define ENFILE          23   /* File table overflow */
#define EMFILE          24   /* Too many open files */
#define ENOTTY          25   /* Not a typewriter (not a terminal) */
#define ETXTBSY         26   /* Text file busy */
#define EFBIG           27   /* File too large */
#define ENOSPC          28   /* No space left on device */
#define ESPIPE          29   /* Illegal seek */
#define EROFS           30   /* Read-only file system */
#define EMLINK          31   /* Too many links */
#define EPIPE           32   /* Broken pipe */

/* Math errors */
#define EDOM            33   /* Math argument out of domain of func */
#define ERANGE          34   /* Math result not representable */

/* Resource deadlock */
#define EDEADLK         35   /* Resource deadlock would occur */
#define ENAMETOOLONG    36   /* File name too long */
#define ENOLCK          37   /* No record locks available */

/* Function not implemented */
#define ENOSYS          38   /* Function not implemented */

/* Directory not empty */
#define ENOTEMPTY       39   /* Directory not empty */

/* Too many symbolic links */
#define ELOOP           40   /* Too many symbolic links encountered */

/* Additional useful errors */
#define EWOULDBLOCK     EAGAIN  /* Operation would block */
#define ENOMSG          42   /* No message of desired type */
#define EIDRM           43   /* Identifier removed */
#define ECHRNG          44   /* Channel number out of range */
#define ENOSTR          45   /* Device not a stream */
#define ENODATA         46   /* No data available */
#define ETIME           47   /* Timer expired */
#define ENOSR           48   /* Out of streams resources */
#define EPROTO          49   /* Protocol error */
#define EBADMSG         50   /* Not a data message */
#define EOVERFLOW       51   /* Value too large for defined data type */
#define EILSEQ          52   /* Illegal byte sequence */
#define EUSERS          53   /* Too many users */
#define ENOTSOCK        54   /* Socket operation on non-socket */
#define EDESTADDRREQ    55   /* Destination address required */
#define EMSGSIZE        56   /* Message too long */
#define EPROTOTYPE      57   /* Protocol wrong type for socket */
#define ENOPROTOOPT     58   /* Protocol not available */
#define EPROTONOSUPPORT 59   /* Protocol not supported */
#define ESOCKTNOSUPPORT 60   /* Socket type not supported */
#define EOPNOTSUPP      61   /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT    62   /* Protocol family not supported */
#define EAFNOSUPPORT    63   /* Address family not supported by protocol */
#define EADDRINUSE      64   /* Address already in use */
#define EADDRNOTAVAIL   65   /* Cannot assign requested address */
#define ENETDOWN        66   /* Network is down */
#define ENETUNREACH     67   /* Network is unreachable */
#define ENETRESET       68   /* Network dropped connection because of reset */
#define ECONNABORTED    69   /* Software caused connection abort */
#define ECONNRESET      70   /* Connection reset by peer */
#define ENOBUFS         71   /* No buffer space available */
#define EISCONN         72   /* Transport endpoint is already connected */
#define ENOTCONN        73   /* Transport endpoint is not connected */
#define ESHUTDOWN       74   /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS    75   /* Too many references: cannot splice */
#define ETIMEDOUT       76   /* Connection timed out */
#define ECONNREFUSED    77   /* Connection refused */
#define EHOSTDOWN       78   /* Host is down */
#define EHOSTUNREACH    79   /* No route to host */
#define EALREADY        80   /* Operation already in progress */
#define EINPROGRESS     81   /* Operation now in progress */

/*
 * Helper macros for returning errors from system calls
 */
#define RETURN_ERROR(errcode)  return -(errcode)
#define IS_ERROR(ret)          ((ret) < 0)
#define GET_ERROR(ret)         (-(ret))

#endif /* TINYOS_ERRNO_H */
