#ifndef _MEMORY_H_
#define _MEMORY_H_

#if __KERNEL__
#include <linux/slab.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#if __KERNEL__
#define xmalloc(n) kmalloc(n, GFP_KERNEL)
#define xrealloc(p, n) krealloc(p, n, GFP_KERNEL)
#define xfree(p) kfree(p);
#else
static void *(*orig_malloc)(size_t) = malloc;
static void *(*orig_realloc)(void *, size_t) = realloc;
static void (*orig_free)(void *) = free;

/* TODO: implement custom memory allocator which fits arbitrary precision
 * operations
 */
static inline void *xmalloc(size_t size)
{
    void *p;
    if (!(p = (*orig_malloc)(size))) {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return p;
}

static inline void *xrealloc(void *ptr, size_t size)
{
    void *p;
    if (!(p = (*orig_realloc)(ptr, size)) && size != 0) {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return p;
}

static inline void xfree(void *ptr)
{
    (*orig_free)(ptr);
}
#endif

#define MALLOC(n) xmalloc(n)
#define REALLOC(p, n) xrealloc(p, n)
#define FREE(p) xfree(p)

#endif /* !_MEMORY_H_ */
