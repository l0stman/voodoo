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
        assert(pos < cbp->len);
        cbp->buf[(cbp->offset + pos) % cbp->size] = c;
}

static inline void
cappend(char c, struct cbuf *cbp)
{
        assert(cbp->len < cbp->size);
        cbp->buf[(cbp->offset + cbp->len++) % cbp->size] = c;
}

#endif  /* !VOODOO_CBUF_H_ */
