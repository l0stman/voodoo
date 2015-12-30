#include <sys/types.h>

#include <limits.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "cbuf.h"
#include "err.h"
#include "utils.h"

struct cbuf *
cbuf(void)
{
        struct cbuf *cbp;

        cbp = malloc_or_die(sizeof(*cbp) + CBUFSIZ);
        cbp->buf = (char *)(cbp+1);
        cbp->offset = 0;
        cbp->len = 0;
        return (cbp);
}

void
cfree(struct cbuf *cbp)
{
        free(cbp);
}

ssize_t
cread(int fd, struct cbuf *cbp, size_t nbytes)
{
        ssize_t nread;
        size_t offset;

        if (nbytes == 0)
                return (nbytes);
        assert(nbytes <= CBUFSIZ - cbp->len);
        offset = (cbp->offset + cbp->len) & CBUFMASK;
        if (offset + nbytes > CBUFSIZ) {
                struct iovec v[2];
                v[0].iov_base = cbp->buf + offset;
                v[0].iov_len = CBUFSIZ - offset;
                v[1].iov_base = cbp->buf;
                v[1].iov_len = offset + nbytes - CBUFSIZ;
                nread = readv_or_die(fd, v, 2);
        } else
                nread = read_or_die(fd, cbp->buf + offset, nbytes);
        cbp->len += nread;
        return (nread);
}

ssize_t
cwrite(int fd, struct cbuf *cbp, size_t nbytes)
{
        ssize_t nwrite;

        if (cbp->len < nbytes)
                err_quit("cwrite: not enough bytes in the buffer");
        if (cbp->offset + nbytes > CBUFSIZ) {
                struct iovec v[2];
                v[0].iov_base = cbp->buf + cbp->offset;
                v[0].iov_len = CBUFSIZ - cbp->offset;
                v[1].iov_base = cbp->buf;
                v[1].iov_len = cbp->offset + nbytes - CBUFSIZ;
                nwrite = writev_or_die(fd, v, 2);
        } else
                nwrite = write_or_die(fd, cbp->buf + cbp->offset, nbytes);
        cbp->len -= nwrite;
        cbp->offset = (cbp->offset + nwrite) & CBUFMASK;
        return (nwrite);
}
