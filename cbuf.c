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

        cbp = malloc_or_die(sizeof(*cbp));
        cbp->buf = malloc_or_die(CBUFSIZ);
        cbp->offset = 0;
        cbp->size = CBUFSIZ;
        cbp->len = 0;
        return (cbp);
}

void
cfree(struct cbuf *cbp)
{
        free(cbp->buf);
        free(cbp);
}

/*
 * Resize the circular buffer pointed by "cbp" to the smallest power
 * of 2 greater or equal to "nbytes + cbp->len" if possible or to
 * "nbytes + cbp->len" if not.  Return the size of the new buffer.
 */
size_t
cresize(size_t nbytes, struct cbuf *cbp)
{
        size_t total, n;
        int i;

        if (SIZE_T_MAX - nbytes < cbp->len)
                err_quit("cresize: not enough memory");
        total = cbp->len + nbytes;
        n = total;
        /* "total" isn't a power of 2 and the left shift won't overflow */
        if ((total & total-1) > 0 && (i = flsll(total)) < flsll(SIZE_T_MAX))
                n = (1 << i);
        cbp->buf = realloc_or_die(cbp->buf, n);
        if (cbp->offset + cbp->len > cbp->size)
                /* Old buffer wrapped around the last element. */
                bcopy(cbp->buf, cbp->buf+cbp->size,
                      cbp->len + cbp->offset - cbp->size);
        cbp->size = n;
        return (n);
}

ssize_t
cread(int fd, struct cbuf *cbp, size_t nbytes)
{
        ssize_t nread;
        size_t offset;

        if (nbytes == 0)
                return (nbytes);
        if (nbytes > cbp->size - cbp->len)
                cresize(nbytes, cbp);
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
        if (cbp->size/2 >= CBUFSIZ && cbp->len <= cbp->size/4) {
                /*
                 * Halve the current buffer size but make sure that
                 * all the contents are in the first half of the
                 * buffer before we proceed.
                 */
                if (cbp->offset + cbp->len > cbp->size) {
                        /* The buffer wraps around the last element. */
                        bcopy(cbp->buf+cbp->offset,
                              cbp->buf+cbp->offset - cbp->size/2,
                              cbp->size - cbp->offset);
                        cbp->offset -= cbp->size/2;
                } else if (cbp->offset + cbp->len > cbp->size/2) {
                        bcopy(cbp->buf + cbp->offset, cbp->buf, cbp->len);
                        cbp->offset = 0;
                }
                cbp->buf = realloc_or_die(cbp->buf, cbp->size/2);
                cbp->size /= 2;
        }
        return (nbytes);
}

/*
 * Move "len" bytes from "src" to "dst".  If the character "c" is
 * encountered during the move, then drop it also from "src" and
 * return 1.  Otherwise "len" bytes have been moved and 0 is
 * returned.
 */
int
cmovec(struct cbuf *src, struct cbuf *dst, char c, size_t len)
{
        size_t i, j, n;
        int ret;

        if (src->len < len)
                err_quit("cmovec: not enough bytes in the source buffer");
        if (len > dst->size - dst->len)
                cresize(len, dst);
        i = src->offset;
        j = (dst->offset + dst->len) % dst->size;
        ret = 0;
        for (n = 0; n < len; n++) {
                ret = (src->buf[i] == c);
                if (ret)
                        break;
                dst->buf[j] = src->buf[i];
                i = (i+1) % src->size;
                j = (j+1) % dst->size;
        }
        dst->len += n;
        if (ret)
                n++;
        src->offset = (src->offset + n) % src->size;
        src->len -= n;
        return (ret);
}
