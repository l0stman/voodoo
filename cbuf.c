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
                nread = read_or_die(fd, cbp->buf + offset, CBUFSIZ - offset);
                nread += read_or_die(fd, cbp->buf, offset + nbytes - CBUFSIZ);
        } else
                nread = read_or_die(fd, cbp->buf + offset, nbytes);
        cbp->len += nread;
        return (nread);
}

ssize_t
cwrite(int fd, struct cbuf *cbp, size_t nbytes)
{
        if (cbp->len < nbytes)
                err_quit("cwrite: not enough bytes in the buffer");
        if (cbp->offset + nbytes > CBUFSIZ) {
                write_or_die(fd, cbp->buf + cbp->offset, CBUFSIZ - cbp->offset);
                write_or_die(fd, cbp->buf, cbp->offset + nbytes - CBUFSIZ);
        } else
                write_or_die(fd, cbp->buf + cbp->offset, nbytes);
        cbp->len -= nbytes;
        cbp->offset = (cbp->offset + nbytes) & CBUFMASK;
        return (nbytes);
}
