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
        cbp->size = CBUFSIZ;
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
        assert(nbytes <= cbp->size - cbp->len);
        offset = (cbp->offset + cbp->len) % cbp->size;
        if (offset + nbytes > cbp->size) {
                nread = read_or_die(fd, cbp->buf + offset, cbp->size - offset);
                nread += read_or_die(fd, cbp->buf, offset + nbytes - cbp->size);
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
        if (cbp->offset + nbytes > cbp->size) {
                write_or_die(fd, cbp->buf + cbp->offset, cbp->size - cbp->offset);
                write_or_die(fd, cbp->buf, cbp->offset + nbytes - cbp->size);
        } else
                write_or_die(fd, cbp->buf + cbp->offset, nbytes);
        cbp->len -= nbytes;
        cbp->offset = (cbp->offset + nbytes) % cbp->size;
        return (nbytes);
}
