#ifndef VOODOO_UTILS_H_
#define VOODOO_UTILS_H_

#include <sys/types.h>
#include <sys/socket.h>

extern ssize_t  read_or_die(int, void *, size_t);
extern ssize_t  write_or_die(int, const void *, size_t);
extern int      socket_or_die(int, int, int);
extern void     *malloc_or_die(size_t);
extern void     *realloc_or_die(void *, size_t);
extern void     setnblock_or_die(int);

#endif
