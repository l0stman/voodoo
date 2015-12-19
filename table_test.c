#include <assert.h>
#include <stdio.h>

#include "table.h"

struct {
        uint32_t k;
        uint32_t v;
} kv[] = {
        {0x6b8b4567, 0x327b23c6},
        {0x643c9869, 0x66334873},
        {0x74b0dc51, 0x19495cff},
        {0x2ae8944a, 0x625558ec},
        {0x238e1f29, 0x46e87ccd},
        {0x3d1b58ba, 0x507ed7ab},
        {0x2eb141f2, 0x41b71efb},
        {0x79e2a9e3, 0x7545e146},
        {0x515f007c, 0x5bd062c2},
        {0x12200854, 0x4db127f8},
        {0x0216231b, 0x1f16e9e8},
        {0x1190cde7, 0x66ef438d},
        {0x140e0f76, 0x3352255a},
        {0x109cf92e, 0x0ded7263},
        {0x7fdcc233, 0x1befd79f},
        {0x41a7c4c9, 0x6b68079a},
        {0x4e6afb66, 0x25e45d32},
        {0x519b500d, 0x431bd7b7},
        {0x3f2dba31, 0x7c83e458},
        {0x257130a3, 0x62bbd95a},
        {0x436c6125, 0x628c895d},
        {0x333ab105, 0x721da317},
        {0x2443a858, 0x2d1d5ae9},
        {0x6763845e, 0x75a2a8d4},
        {0x08edbdab, 0x79838cb2},
        {0x4353d0cd, 0x0b03e0c6},
        {0x189a769b, 0x54e49eb4},
        {0x71f32454, 0x2ca88611},
        {0x0836c40e, 0x02901d82},
        {0x3a95f874, 0x08138641},
        {0x1e7ff521, 0x7c3dbd3d},
        {0x737b8ddc, 0x6ceaf087},
        {0x22221a70, 0x4516dde9}
};

#define NELEMS(x)       (sizeof(x)/sizeof((x)[0]))
#define KSIZE           (sizeof(kv[0].k))
#define ASSERT_PUT(t, i)        do {                                     \
                table_put(t, (char *)&kv[i].k, KSIZE, (char *)&kv[i].v); \
                assert(table_get(t, (char *)&kv[i].k, KSIZE));           \
        } while (0)
#define ASSERT_DEL(t, i)        do {                            \
                table_del(t, (char *)&kv[i].k, KSIZE);          \
                assert(!table_get(t, (char *)&kv[i].k, KSIZE)); \
        } while (0)

int
main(void)
{
        struct table *t;
        struct bucket *bp;
        int i;
        uint32_t N, old;

        t = default_table();
        N = t->rehash_thres*t->size;
        assert(N < NELEMS(kv));
        old = t->size;
        for (i = 0; i < N; i++)
                ASSERT_PUT(t, i);
        assert(old  == t->size);
        ASSERT_PUT(t, N);
        assert((old << 1) == t->size);
        TABLE_FOREACH(bp, t)
                printf("0x%08x: 0x%08x\n",
                       *(uint32_t *)bp->key,
                       *(uint32_t *)bp->val);
        N = t->rehash_thres*t->size/4;
        old = t->size;
        for (i = t->nelems; i >= N; i--)
                ASSERT_DEL(t, i);
        assert(old == t->size);
        ASSERT_DEL(t, N-1);
        assert((old >> 1) == t->size);
        for (i = N-2; i >= 0; i--)
                ASSERT_DEL(t, i);
        assert(t->nelems == 0);
        free_table(t);
        return (0);
}
