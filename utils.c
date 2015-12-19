#include <sys/types.h>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "err.h"
#include "utils.h"

ssize_t
read_or_die(int fd, void *buf, size_t nbytes)
{
        ssize_t n;

        if ((n = read(fd, buf, nbytes)) == -1)
                err_sys("read");
        return (n);
}

ssize_t
write_or_die(int fd, const void *buf, size_t nbytes)
{
        ssize_t n;

        if ((n = write(fd, buf, nbytes)) == -1)
                err_sys("write");
        return (n);
}

int
socket_or_die(int domain, int type, int protocol)
{
        int s;

        if ((s = socket(domain, type, protocol)) < 0)
                err_sys("socket");
        return (s);
}

void *
malloc_or_die(size_t size)
{
        void *ptr;

        if ((ptr = malloc(size)) == NULL)
                err_sys("malloc");
        return (ptr);
}

void *
calloc_or_die(size_t number, size_t size)
{
        void *ptr;

        if ((ptr = calloc(number, size)) == NULL)
                err_sys("calloc");
        return (ptr);
}

void *
realloc_or_die(void *ptr, size_t size)
{
        if ((ptr = realloc(ptr, size)) == NULL)
                err_sys("realloc");
        return (ptr);
}

void
setnblock_or_die(int fd)
{
        int flags;

        if ((flags = fcntl(fd, F_GETFD)) == -1)
                err_sys("fcntl");
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFD, flags) == -1)
                err_sys("fcntl");
}
