#ifndef VOODOO_CBUF_H_
#define VOODOO_CBUF_H_

#include <assert.h>

#define CBUFSIZ         1024            /* should be a power of 2 */
#define CBUFMASK        (CBUFSIZ-1)

struct cbuf {
        char    *buf;
        size_t  offset;
        size_t  len;
};

extern struct cbuf *cbuf(void);
extern void     cfree(struct cbuf *);
extern ssize_t  cread(int, struct cbuf *, size_t);
extern ssize_t  cwrite(int , struct cbuf *, size_t);

static inline char
cref(const struct cbuf *cbp, size_t pos)
{
        assert(pos < cbp->len);
        return (cbp->buf[(cbp->offset + pos) & CBUFMASK]);
}

static inline void
cset(char c, size_t pos, struct cbuf *cbp)
{
        assert(pos < cbp->len);
        cbp->buf[(cbp->offset + pos) & CBUFMASK] = c;
}

static inline void
cappend(char c, struct cbuf *cbp)
{
        assert(cbp->len < CBUFSIZ);
        cbp->buf[(cbp->offset + cbp->len++) & CBUFMASK] = c;
}

#endif  /* !VOODOO_CBUF_H_ */
