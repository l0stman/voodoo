#ifndef VOODOO_TABLE_H_
#define VOODOO_TABLE_H_

#include <sys/queue.h>
#include <stdint.h>

struct bucket {
        const char      *key;
        uint8_t         len;
        void            *val;
        SLIST_ENTRY(bucket) next_bucket;
        LIST_ENTRY(bucket)  elems;
};

struct chunk {
        SLIST_ENTRY(chunk) next;
};

struct table {
        const uint8_t   secret_key[16];
        const float     rehash_thres;
        uint32_t        size;
        uint32_t        nelems;
        SLIST_HEAD(, bucket) *table;
        SLIST_HEAD(, bucket) free_buckets;
        SLIST_HEAD(, chunk)  chunks;
        LIST_HEAD(, bucket)  elems;
};

#define TABLE_FOREACH(bp, t)    LIST_FOREACH(bp, &t->elems, elems)

struct table *default_table(void);
struct table *table(uint32_t);
void free_table(struct table *);
void table_put(struct table *, const char *, uint8_t, void *);
void *table_get(const struct table *, const char *, uint8_t);
void table_del(struct table *, const char *, uint8_t);

#endif  /* !VOODOO_TABLE_H_ */
