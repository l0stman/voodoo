#include <stdlib.h>
#include <strings.h>
#include <stdint.h>
#include <crypto/siphash/siphash.h>

#include "table.h"
#include "utils.h"

static const uint32_t min_table_size = 1 << 4;
static const uint32_t max_table_size = 1 << 16;

static struct bucket *
bucket(struct table *t)
{
        struct bucket *bp = NULL;

        if (SLIST_EMPTY(&(t->free_buckets))) {
                struct chunk *cp;
                struct bucket *p;
                cp = malloc_or_die(sizeof(*cp)+sizeof(*bp)*t->size);
                bp = (struct bucket *)(cp+1);
                p = bp+t->size-1;
                SLIST_NEXT(p, next_bucket) = NULL;
                while (--p >= bp)
                        SLIST_NEXT(p, next_bucket) = p+1;
                SLIST_FIRST(&t->free_buckets) = bp;
                SLIST_INSERT_HEAD(&t->chunks, cp, next);
        }
        bp = SLIST_FIRST(&t->free_buckets);
        SLIST_REMOVE_HEAD(&t->free_buckets, next_bucket);
        return (bp);
}

struct table *
table(uint32_t size_hint)
{
        struct table *t;
        uint32_t s;

        for (s = min_table_size; s < size_hint && s < max_table_size; s <<= 1)
                ;
        t = malloc_or_die(sizeof(*t));
        arc4random_buf((void *)t->secret_key, sizeof(t->secret_key));
        *(float *)&t->rehash_thres = 2;
        t->size = s;
        t->nelems = 0;
        t->table = calloc_or_die(s, sizeof(*t->table));
        SLIST_INIT(&t->free_buckets);
        SLIST_INIT(&t->chunks);
        LIST_INIT(&t->elems);
        return (t);
}

struct table *
default_table(void)
{
        return table(min_table_size);
}

void
free_table(struct table *t)
{
        struct chunk *cp, *tmp;

        SLIST_FOREACH_SAFE(cp, &t->chunks, next, tmp)
                free(cp);
        free(t->table);
        free(t);
}

static inline uint32_t
hash32(const struct table *t, const char *key, uint8_t len)
{
        SIPHASH_CTX ctx;
        uint64_t h;

        h = SipHash24(&ctx, t->secret_key, key, len);
        return (h & (t->size-1));
}

static void
rehash(struct table *t, uint32_t size)
{
        struct bucket *bp = NULL;

        t->size = size;
        free(t->table);
        t->table = calloc_or_die(t->size, sizeof(*t->table));
        TABLE_FOREACH(bp, t) {
                uint32_t h = hash32(t, bp->key, bp->len);
                SLIST_INSERT_HEAD(t->table+h, bp, next_bucket);
        }
}

static inline struct bucket *
table_find(const struct table *t, const char *key, uint8_t len, uint32_t* hp)
{
        struct bucket *bp;
        uint32_t h;

        h = hash32(t, key, len);
        if (hp)
                *hp = h;
        SLIST_FOREACH(bp, t->table+h, next_bucket)
                if (bequal(key, len, bp->key, bp->len))
                        return (bp);
        return (NULL);
}

void *
table_get(const struct table *t, const char *key, uint8_t len)
{
        struct bucket *bp;

        bp = table_find(t, key, len, NULL);
        return (void *)(bp && bp->val);
}

void
table_put(struct table *t, const char *key, uint8_t len, void *val)
{
        struct bucket *bp;
        uint32_t h;

        if (t->rehash_thres < (t->nelems+1.0)/t->size &&
            t->size < max_table_size) {
                rehash(t, t->size << 1);
        }
        if ((bp = table_find(t, key, len, &h)) != NULL) {
                bp->val = val;
                return;
        }
        bp = bucket(t);
        bp->key = key;
        bp->len = len;
        bp->val = val;
        t->nelems++;
        SLIST_INSERT_HEAD(t->table+h, bp, next_bucket);
        LIST_INSERT_HEAD(&t->elems, bp, elems);
}

void
table_del(struct table *t, const char *key, uint8_t len)
{
        struct bucket *bp, *next, *prev;
        uint32_t h;

        if (4*(t->nelems-1.0)/t->size < t->rehash_thres &&
            t->size > min_table_size) {
                rehash(t, t->size >> 1);
        }
        h = hash32(t, key, len);
        prev = NULL;
        SLIST_FOREACH_SAFE(bp, t->table+h, next_bucket, next) {
                if (bequal(key, len, bp->key, bp->len)) {
                        if (prev == NULL)
                                SLIST_REMOVE_HEAD(t->table+h, next_bucket);
                        else
                                SLIST_REMOVE_AFTER(prev, next_bucket);
                        --t->nelems;
                        SLIST_INSERT_HEAD(&t->free_buckets, bp, next_bucket);
                        LIST_REMOVE(bp, elems);
                        return;
                }
                prev = bp;
        }
}
