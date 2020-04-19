#include <linux/kernel.h>
#include <linux/slab.h>

#include "bn.h"

/* Compute the Nth Fibonnaci number F_n, where
 * F_0 = 0
 * F_1 = 1
 * F_n = F_{n-1} + F_{n-2} for n >= 2.
 *
 * This is based on the matrix identity:
 *        n
 * [ 0 1 ]  = [ F_{n-1}    F_n   ]
 * [ 1 1 ]    [   F_n    F_{n+1} ]
 *
 * Exponentiation uses binary power algorithm from high bit to low bit.
 */
static void fibonacci(uint64_t n, bn *fib)
{
    if (unlikely(n <= 2)) {
        if (n == 0)
            bn_zero(fib);
        else
            bn_set_u32(fib, 1);
        return;
    }

    bn *a1 = fib; /* Use output param fib as a1 */

    bn_t a0, tmp, a;
    bn_init_u32(a0, 0); /*  a0 = 0 */
    bn_set_u32(a1, 1);  /*  a1 = 1 */
    bn_init(tmp);       /* tmp = 0 */
    bn_init(a);

    /* Start at second-highest bit set. */
    for (uint64_t k = ((uint64_t) 1) << (62 - __builtin_clzll(n)); k; k >>= 1) {
        /* Both ways use two squares, two adds, one multipy and one shift. */
        bn_lshift(a0, 1, a); /* a03 = a0 * 2 */
        bn_add(a, a1, a);    /*   ... + a1 */
        bn_sqr(a1, tmp);     /* tmp = a1^2 */
        bn_sqr(a0, a0);      /* a0 = a0 * a0 */
        bn_add(a0, tmp, a0); /*  ... + a1 * a1 */
        bn_mul(a1, a, a1);   /*  a1 = a1 * a */
        if (k & n) {
            bn_swap(a1, a0);    /*  a1 <-> a0 */
            bn_add(a0, a1, a1); /*  a1 += a0 */
        }
    }
    /* Now a1 (alias of output parameter fib) = F[n] */

    bn_free(a0);
    bn_free(tmp);
    bn_free(a);
}

char *eval_fib(size_t n)
{
    bn_t fib = BN_INITIALIZER;

    fibonacci(n, fib);

    preempt_disable();
    char *ptr = bn_return(fib);
    preempt_enable();

    bn_free(fib);
    return ptr;
}
