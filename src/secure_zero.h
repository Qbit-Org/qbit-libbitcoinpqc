#ifndef LIBBITCOINPQC_SECURE_ZERO_H
#define LIBBITCOINPQC_SECURE_ZERO_H

#include <stddef.h>
#include <string.h>

static inline void bitcoin_pqc_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len > 0) {
        *p++ = 0;
        len--;
    }
}

/*
 * Bytes of released stack that bitcoin_pqc_burn_stack() overwrites. The SHA-2
 * compression functions keep the message schedule and working variables in
 * locals that may spill to the stack, and that schedule is reversible to the
 * hashed block (SK_SEED, SK_PRF, derived seeds). Burning once when a
 * secret-key entry point returns covers every frame the call released, at the
 * cost of one wipe per call rather than one per compression.
 *
 * Optimized native keygen/sign use about 13 KiB below the entry point (GCC -O2,
 * x86-64, AVX2 path; measured by painting the stack). Unoptimized builds can
 * use far more (the AVX2 8-way transform alone takes ~190 KiB at -O0) and are
 * not covered. Emscripten's default 64 KiB stack needs a smaller burn; its
 * reference SHA-2 keeps the schedule in WASM locals rather than linear memory.
 */
#ifndef BITCOIN_PQC_BURN_STACK_BYTES
#if defined(__EMSCRIPTEN__)
#define BITCOIN_PQC_BURN_STACK_BYTES (16u * 1024u)
#else
#define BITCOIN_PQC_BURN_STACK_BYTES (64u * 1024u)
#endif
#endif

/* memset through a volatile function pointer so the wipe is not removed as a
   dead store to a dying array. */
static void *(*const volatile bitcoin_pqc_burn_memset)(void *, int, size_t) = memset;

/* Must not be inlined: the scratch array has to occupy the frames the
   just-returned call released, below the caller's frame. "unused" keeps
   translation units that include this header without burning quiet. */
#if defined(__GNUC__) || defined(__clang__)
#define BITCOIN_PQC_BURN_STACK_ATTRS __attribute__((noinline, unused))
#elif defined(_MSC_VER)
#define BITCOIN_PQC_BURN_STACK_ATTRS __declspec(noinline)
#else
#define BITCOIN_PQC_BURN_STACK_ATTRS
#endif

static BITCOIN_PQC_BURN_STACK_ATTRS void bitcoin_pqc_burn_stack(void) {
    unsigned char scratch[BITCOIN_PQC_BURN_STACK_BYTES];

    bitcoin_pqc_burn_memset(scratch, 0, sizeof(scratch));
}

#endif /* LIBBITCOINPQC_SECURE_ZERO_H */
