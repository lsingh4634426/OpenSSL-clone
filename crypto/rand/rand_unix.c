/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"
#include "internal/rand_int.h"
#include <stdio.h>
#ifdef OPENSSL_SYS_UNIX
# include <sys/types.h>
# include <unistd.h>
# include <sys/time.h>

static uint64_t get_time64(void);

/* Macro to convert two thirty two bit values into a sixty four bit one */
#define TWO32TO64(a, b) ((((uint64_t)(a)) << 32) + (b))

/*
 * Check for the existence and support of POSIX timers.  The standard
 * says that the _POSIX_TIMERS macro will have a positive value if they
 * are available.
 *
 * However, we want an additional constraint: that the timer support does
 * not require an extra library dependency.  Early versions of glibc
 * require -lrt to be specified on the link line to access the timers,
 * so this needs to be checked for.
 *
 * It is worse because some libraries define __GLIBC__ but don't
 * support the version testing macro (e.g. uClibc).  This means
 * an extra check is needed.
 *
 * The final condition is:
 *      "have posix timers and either not glibc or glibc without -lrt"
 *
 * The nested #if sequences are required to avoid using a parameterised
 * macro that might be undefined.
 */
#undef OSSL_POSIX_TIMER_OKAY
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
# if defined(__GLIBC__)
#  if defined(__GLIBC_PREREQ)
#   if __GLIBC_PREREQ(2, 17)
#    define OSSL_POSIX_TIMER_OKAY
#   endif
#  endif
# else
#  define OSSL_POSIX_TIMER_OKAY
# endif
#endif

/* Macro to convert two thirty two bit values into a sixty four bit one */
#define TWO32TO64(a, b) ((((uint64_t)(a)) << 32) + (b))

/*
 * Check for the existence and support of POSIX timers.  The standard
 * says that the _POSIX_TIMERS macro will have a positive value if they
 * are available.
 *
 * However, we want an additional constraint: that the timer support does
 * not require an extra library dependency.  Early versions of glibc
 * require -lrt to be specified on the link line to access the timers,
 * so this needs to be checked for.
 *
 * It is worse because some libraries define __GLIBC__ but don't
 * support the version testing macro (e.g. uClibc).  This means
 * an extra check is needed.
 *
 * The final condition is:
 *      "have posix timers and either not glibc or glibc without -lrt"
 *
 * The nested #if sequences are required to avoid using a parameterised
 * macro that might be undefined.
 */
#undef OSSL_POSIX_TIMER_OKAY
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
# if defined(__GLIBC__)
#  if defined(__GLIBC_PREREQ)
#   if __GLIBC_PREREQ(2, 17)
#    define OSSL_POSIX_TIMER_OKAY
#   endif
#  endif
# else
#  define OSSL_POSIX_TIMER_OKAY
# endif
#endif

/* Macro to convert two thirty two bit values into a sixty four bit one */
# define TWO32TO64(a, b) ((((uint64_t)(a)) << 32) + (b))

/*
 * Check for the existence and support of POSIX timers.  The standard
 * says that the _POSIX_TIMERS macro will have a positive value if they
 * are available.
 *
 * However, we want an additional constraint: that the timer support does
 * not require an extra library dependency.  Early versions of glibc
 * require -lrt to be specified on the link line to access the timers,
 * so this needs to be checked for.
 *
 * It is worse because some libraries define __GLIBC__ but don't
 * support the version testing macro (e.g. uClibc).  This means
 * an extra check is needed.
 *
 * The final condition is:
 *      "have posix timers and either not glibc or glibc without -lrt"
 *
 * The nested #if sequences are required to avoid using a parameterised
 * macro that might be undefined.
 */
# undef OSSL_POSIX_TIMER_OKAY
# if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
#  if defined(__GLIBC__)
#   if defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 17)
#     define OSSL_POSIX_TIMER_OKAY
#    endif
#   endif
#  else
#   define OSSL_POSIX_TIMER_OKAY
#  endif
# endif
#endif


#if (defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI)) && \
        !defined(OPENSSL_RAND_SEED_NONE)
# error "UEFI and VXWorks only support seeding NONE"
#endif

#if !(defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32) \
    || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_VXWORKS) \
    || defined(OPENSSL_SYS_UEFI))

# if defined(OPENSSL_SYS_VOS)

#  ifndef OPENSSL_RAND_SEED_OS
#   error "Unsupported seeding method configured; must be os"
#  endif

#  if defined(OPENSSL_SYS_VOS_HPPA) && defined(OPENSSL_SYS_VOS_IA32)
#   error "Unsupported HP-PA and IA32 at the same time."
#  endif
#  if !defined(OPENSSL_SYS_VOS_HPPA) && !defined(OPENSSL_SYS_VOS_IA32)
#   error "Must have one of HP-PA or IA32"
#  endif

/*
 * The following algorithm repeatedly samples the real-time clock (RTC) to
 * generate a sequence of unpredictable data.  The algorithm relies upon the
 * uneven execution speed of the code (due to factors such as cache misses,
 * interrupts, bus activity, and scheduling) and upon the rather large
 * relative difference between the speed of the clock and the rate at which
 * it can be read.  If it is ported to an environment where execution speed
 * is more constant or where the RTC ticks at a much slower rate, or the
 * clock can be read with fewer instructions, it is likely that the results
 * would be far more predictable.  This should only be used for legacy
 * platforms.
 *
 * As a precaution, we assume only 2 bits of entropy per byte.
 */
size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
    short int code;
    int i, k;
    size_t bytes_needed;
    struct timespec ts;
    unsigned char v;
#  ifdef OPENSSL_SYS_VOS_HPPA
    long duration;
    extern void s$sleep(long *_duration, short int *_code);
#  else
    long long duration;
    extern void s$sleep2(long long *_duration, short int *_code);
#  endif

    bytes_needed = rand_pool_bytes_needed(pool, 2 /*entropy_per_byte*/);

    for (i = 0; i < bytes_needed; i++) {
        /*
         * burn some cpu; hope for interrupts, cache collisions, bus
         * interference, etc.
         */
        for (k = 0; k < 99; k++)
            ts.tv_nsec = random();

#  ifdef OPENSSL_SYS_VOS_HPPA
        /* sleep for 1/1024 of a second (976 us).  */
        duration = 1;
        s$sleep(&duration, &code);
#  else
        /* sleep for 1/65536 of a second (15 us).  */
        duration = 1;
        s$sleep2(&duration, &code);
#  endif

        /* Get wall clock time, take 8 bits. */
        clock_gettime(CLOCK_REALTIME, &ts);
        v = (unsigned char)(ts.tv_nsec & 0xFF);
        rand_pool_add(pool, arg, &v, sizeof(v) , 2);
    }
    return rand_pool_entropy_available(pool);
}

# else

#  if defined(OPENSSL_RAND_SEED_EGD) && \
        (defined(OPENSSL_NO_EGD) || !defined(DEVRANDOM_EGD))
#   error "Seeding uses EGD but EGD is turned off or no device given"
#  endif

#  if defined(OPENSSL_RAND_SEED_DEVRANDOM) && !defined(DEVRANDOM)
#   error "Seeding uses urandom but DEVRANDOM is not configured"
#  endif

#  if defined(OPENSSL_RAND_SEED_OS)
#   if !defined(DEVRANDOM)
#    error "OS seeding requires DEVRANDOM to be configured"
#   endif
#   define OPENSSL_RAND_SEED_DEVRANDOM
#   if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#    if __GLIBC_PREREQ(2, 25)
#     define OPENSSL_RAND_SEED_GETRANDOM
#    endif
#   endif
#  endif

#  ifdef OPENSSL_RAND_SEED_GETRANDOM
#   include <sys/random.h>
#  endif

#  if defined(OPENSSL_RAND_SEED_LIBRANDOM)
#   error "librandom not (yet) supported"
#  endif

/*
 * Try the various seeding methods in turn, exit when successful.
 *
 * TODO(DRBG): If more than one entropy source is available, is it
 * preferable to stop as soon as enough entropy has been collected
 * (as favored by @rsalz) or should one rather be defensive and add
 * more entropy than requested and/or from different sources?
 *
 * Currently, the user can select multiple entropy sources in the
 * configure step, yet in practice only the first available source
 * will be used. A more flexible solution has been requested, but
 * currently it is not clear how this can be achieved without
 * overengineering the problem. There are many parameters which
 * could be taken into account when selecting the order and amount
 * of input from the different entropy sources (trust, quality,
 * possibility of blocking).
 */
size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
#  ifdef OPENSSL_RAND_SEED_NONE
    return rand_pool_entropy_available(pool);
#  else
    size_t bytes_needed;
    size_t entropy_available = 0;
    unsigned char *buffer;

#   ifdef OPENSSL_RAND_SEED_GETRANDOM
    bytes_needed = rand_pool_bytes_needed(pool, 8 /*entropy_per_byte*/);
    buffer = rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;

        if (getrandom(buffer, bytes_needed, 0) == (int)bytes_needed)
            bytes = bytes_needed;

        rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   if defined(OPENSSL_RAND_SEED_LIBRANDOM)
    {
        /* Not yet implemented. */
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_DEVRANDOM
    bytes_needed = rand_pool_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        static const char *paths[] = { DEVRANDOM, NULL };
        FILE *fp;
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            if ((fp = fopen(paths[i], "rb")) == NULL)
                continue;
            setbuf(fp, NULL);
            buffer = rand_pool_add_begin(pool, bytes_needed);
            if (buffer != NULL) {
                size_t bytes = 0;
                if (fread(buffer, 1, bytes_needed, fp) == bytes_needed)
                    bytes = bytes_needed;

                rand_pool_add_end(pool, bytes, 8 * bytes);
                entropy_available = rand_pool_entropy_available(pool);
            }
            fclose(fp);
            if (entropy_available > 0)
                return entropy_available;

            bytes_needed = rand_pool_bytes_needed(pool, 8 /*entropy_per_byte*/);
        }
    }
#   endif

#   ifdef OPENSSL_RAND_SEED_RDTSC
    entropy_available = rand_acquire_entropy_from_tsc(pool);
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   ifdef OPENSSL_RAND_SEED_RDCPU
    entropy_available = rand_acquire_entropy_from_cpu(pool);
    if (entropy_available > 0)
        return entropy_available;
#   endif

#   ifdef OPENSSL_RAND_SEED_EGD
    bytes_needed = rand_pool_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        static const char *paths[] = { DEVRANDOM_EGD, NULL };
        int i;

        for (i = 0; paths[i] != NULL; i++) {
            buffer = rand_pool_add_begin(pool, bytes_needed);
            if (buffer != NULL) {
                size_t bytes = 0;
                int num = RAND_query_egd_bytes(paths[i],
                                               buffer, (int)bytes_needed);
                if (num == (int)bytes_needed)
                    bytes = bytes_needed;

                rand_pool_add_end(pool, bytes, 8 * bytes);
                entropy_available = rand_pool_entropy_available(pool);
            }
            if (entropy_available > 0)
                return entropy_available;
        }
    }
#   endif

    return rand_pool_entropy_available(pool);
#  endif
}
# endif
#endif

#ifdef OPENSSL_SYS_UNIX
int rand_pool_add_nonce_data(RAND_POOL *pool)
{
    struct {
        gid_t curr_gid;
        pid_t curr_pid;
        uid_t curr_uid;
        uint64_t curr_time;
    } data;

    /*
     * Add gid, pid, and uid to nonce to ensure variation between
     * different processes.
     */
    data.curr_gid = getgid();
    data.curr_pid = getpid();
    data.curr_uid = getuid();
    data.curr_time = get_time64();

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

int rand_pool_add_additional_data(RAND_POOL *pool)
{
    struct {
        CRYPTO_THREAD_ID curr_tid;
        uint64_t curr_time;
    } data;

    data.curr_tid = CRYPTO_THREAD_get_current_id();
    data.curr_time = OPENSSL_rdtsc();

    if (data.curr_time == 0)
        data.curr_time = get_time64();

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}



/*
 * Find a suitable source of time.  Start with the highest resolution source
 * and work down to the slower ones.  This is added to the nonce or additional data
 * and isn't counted as randomness, so any result is acceptable.
 *
 * Returns 0 when we weren't able to find any time source
 */
static uint64_t get_time64(void)
{
# if defined(__sun) || defined(__hpux)
    return gethrtime();
# elif defined(_AIX)
    {
        timebasestruct_t t;

        read_wall_time(&t, TIMEBASE_SZ);
        return TWO32TO64(t.tb_high, t.tb_low);
    }
# elif defined(OSSL_POSIX_TIMER_OKAY)
    {
        struct timespec ts;
        clockid_t cid;

#  ifdef CLOCK_BOOTTIME
        cid = CLOCK_BOOTTIME;
#  elif defined(_POSIX_MONOTONIC_CLOCK)
        cid = CLOCK_MONOTONIC;
#  else
        cid = CLOCK_REALTIME;
#  endif

        if (clock_gettime(cid, &ts) == 0)
            return TWO32TO64(ts.tv_sec, ts.tv_nsec);
    }
# endif
# if defined(__unix__) \
     || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
    {
        struct timeval tv;

        if (gettimeofday(&tv, NULL) == 0)
            return TWO32TO64(tv.tv_sec, tv.tv_usec);
    }
# endif
    {
        // TODO: OPENSSL_rdtsc() was moved to the end, because its
        // return type was declared as uint32_t in d807db26a403.
        // So it returns only 32 timer bits even if the platform
        // would supports 64 bits.
        uint32_t res = OPENSSL_rdtsc();

        if (res != 0)
            return res;
    }

    {
        time_t t = time(NULL);
        if (t == (time_t)-1)
            return 0;
        return t;
    }
}
#endif
