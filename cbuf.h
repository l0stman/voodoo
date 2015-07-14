#ifndef VOODOO_CBUF_H_
#define VOODOO_CBUF_H_

#include <assert.h>

#define CBUFSIZ 1024

struct cbuf {
        char    *buf;
        size_t  offset;
        size_t  size;
        size_t  len;
};

extern struct cbuf *cbuf(void);
extern void     cfree(struct cbuf *);
extern ssize_t  cread(int, struct cbuf *, size_t);
extern ssize_t  cwrite(int , struct cbuf *, size_t);
extern size_t   cresize(size_t, struct cbuf *);
extern int      cmovec(struct cbuf *, struct cbuf *, char, size_t);

static inline char
cref(const struct cbuf *cbp, size_t pos)
{
        assert(pos < cbp->len);
        return (cbp->buf[(cbp->offset + pos) % cbp->size]);
}

static inline void
cset(char c, size_t pos, struct cbuf *cbp)
{
        assert(pos <= cbp->len);
        if (pos == cbp->len && cbp->len == cbp->size)
                cresize(1, cbp);
        cbp->buf[(cbp->offset + pos) % cbp->size] = c;
        if (++pos > cbp->len)
                cbp->len = pos;
}

#endif  /* !VOODOO_CBUF_H_ */
