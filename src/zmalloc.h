/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ZMALLOC_H
#define __ZMALLOC_H

/* Double expansion needed for stringification of macro values. */
#define __xstr(s) __str(s)
#define __str(s) #s

#if defined(USE_TCMALLOC)
#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))
#include <google/tcmalloc.h>
#if (TC_VERSION_MAJOR == 1 && TC_VERSION_MINOR >= 6) || (TC_VERSION_MAJOR > 1)
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) tc_malloc_size(p)
#else
#error "Newer version of tcmalloc required"
#endif

#elif defined(USE_JEMALLOC)
#define ZMALLOC_LIB ("jemalloc-" __xstr(JEMALLOC_VERSION_MAJOR) "." __xstr(JEMALLOC_VERSION_MINOR) "." __xstr(JEMALLOC_VERSION_BUGFIX))
#include <jemalloc/jemalloc.h>
#if (JEMALLOC_VERSION_MAJOR == 2 && JEMALLOC_VERSION_MINOR >= 1) || (JEMALLOC_VERSION_MAJOR > 2)
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) je_malloc_usable_size(p)
#else
#error "Newer version of jemalloc required"
#endif

#elif defined(__APPLE__)
#include <malloc/malloc.h>
#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) malloc_size(p)
#endif

/* On native libc implementations, we should still do our best to provide a
 * HAVE_MALLOC_SIZE capability. This can be set explicitly as well:
 *
 * NO_MALLOC_USABLE_SIZE disables it on all platforms, even if they are
 *      known to support it.
 *  // malloc_usable_size Linux下获取malloc实际分配的内存大小
 * USE_MALLOC_USABLE_SIZE forces use of malloc_usable_size() regardless
 *      of platform.
 */
#ifndef ZMALLOC_LIB
#define ZMALLOC_LIB "libc"

#if !defined(NO_MALLOC_USABLE_SIZE) && \
    (defined(__GLIBC__) || defined(__FreeBSD__) || \
     defined(__DragonFly__) || defined(__HAIKU__) || \
     defined(USE_MALLOC_USABLE_SIZE))

/* Includes for malloc_usable_size() */
#ifdef __FreeBSD__
#include <malloc_np.h>
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <malloc.h>
#endif

#define HAVE_MALLOC_SIZE 1
#define zmalloc_size(p) malloc_usable_size(p)

#endif
#endif

// 定义通用的 zmalloc_size 实现， zmalloc_size在不同内存管理器里面调用不同实现


/* We can enable the Redis defrag capabilities only if we are using Jemalloc
 * and the version used is our special version modified for Redis having
 * the ability to return per-allocation fragmentation hints. */
// 仅使用Jemalloc时且 Jemalloc 是修改过的特殊版本有能力返回每个分配碎片命中， 自动内存碎片整理（Active Defrag） 
#if defined(USE_JEMALLOC) && defined(JEMALLOC_FRAG_HINT)
#define HAVE_DEFRAG
#endif

/* 'noinline' attribute is intended to prevent the `-Wstringop-overread` warning
 * when using gcc-12 later with LTO enabled. It may be removed once the
 * bug[https://gcc.gnu.org/bugzilla/show_bug.cgi?id=96503] is fixed. */

//
// 开启LTO主要有这几点好处
// （1）将一些函数內联化
// （2）去除了一些无用代码
// （3）对程序有全局的优化作用

 // 三种不同内存申请函数

 // attribute((malloc)) 是由如此标记的函数返回的块不得包含任何指向其他对象的指针.目的是帮助编译器估计哪些指针可能指向同一个对象：该属性告诉GCC它不必担心你的函数返回的对象可能包含指向它正在跟踪的其他东西的指针.
 // attribute((alloc_size))
 // attribute((noinline)) function attribute与上面的相反，声明为非内联函数

 // 分配需要的内存大小
__attribute__((malloc,alloc_size(1),noinline)) void *zmalloc(size_t size);

// 分配需要的内存并清 0
__attribute__((malloc,alloc_size(1),noinline)) void *zcalloc(size_t size);


// 根据 num 和 size 分配内存
__attribute__((malloc,alloc_size(1,2),noinline)) void *zcalloc_num(size_t num, size_t size);

// 在原指针的基础上重新分配内存并清 0， 如果内存充足，返回原地址，不充足，非新申请一块位置
__attribute__((alloc_size(2),noinline)) void *zrealloc(void *ptr, size_t size);


// 尝试分配内存，和上面区别是，分配失败返回空指针，不 crash
__attribute__((malloc,alloc_size(1),noinline)) void *ztrymalloc(size_t size);

__attribute__((malloc,alloc_size(1),noinline)) void *ztrycalloc(size_t size);
__attribute__((alloc_size(2),noinline)) void *ztryrealloc(void *ptr, size_t size);

// 释放内存
void zfree(void *ptr);
// The value returned by malloc_usable_size() may be greater than
//    the requested size of the allocation because of alignment and
//    minimum size constraints.  Although the excess bytes can be
//    overwritten by the application without ill effects, this is not
//    good programming practice: the number of excess bytes in an
//    allocation depends on the underlying implementation.
//  动态内存分配并返回可用内存大小 usable； usable 通过 malloc_usable_size返回实际申请的内存大小
// 由于内存对齐和最小内存限制，申请内存可能会大于需要的内存
// 可以使用这部分超出实际需要大小的内存，且没有影响，但这不是一个好的实践，且超出的字节数取决了不同系统实现
void *zmalloc_usable(size_t size, size_t *usable);
void *zcalloc_usable(size_t size, size_t *usable);
void *zrealloc_usable(void *ptr, size_t size, size_t *usable);
void *ztrymalloc_usable(size_t size, size_t *usable);
void *ztrycalloc_usable(size_t size, size_t *usable);
void *ztryrealloc_usable(void *ptr, size_t size, size_t *usable);
void zfree_usable(void *ptr, size_t *usable);

/**
 * @brief 复制字符串
 * 
 *
 * @param s 字符串的地址
 * @return 返回新建字符串的地址
 */
__attribute__((malloc)) char *zstrdup(const char *s);

/**
 * @brief 返回已使用的内存
 * 
 *
 * @param  
 * @return 
 */
size_t zmalloc_used_memory(void);

// 设置 oom handler 处理
void zmalloc_set_oom_handler(void (*oom_handler)(size_t));

/**
 * @brief 获取实际使用的物理内存
 * 
 *
 * @param  
 * @return 
 */
size_t zmalloc_get_rss(void);

int zmalloc_get_allocator_info(size_t *allocated, size_t *active, size_t *resident);
void set_jemalloc_bg_thread(int enable);
int jemalloc_purge(void);
size_t zmalloc_get_private_dirty(long pid);
size_t zmalloc_get_smap_bytes_by_field(char *field, long pid);
size_t zmalloc_get_memory_size(void);
void zlibc_free(void *ptr);
void zmadvise_dontneed(void *ptr);

#ifdef HAVE_DEFRAG
void zfree_no_tcache(void *ptr);
__attribute__((malloc)) void *zmalloc_no_tcache(size_t size);
#endif

#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr);
size_t zmalloc_usable_size(void *ptr);
#else
/* If we use 'zmalloc_usable_size()' to obtain additional available memory size
 * and manipulate it, we need to call 'extend_to_usable()' afterwards to ensure
 * the compiler recognizes this extra memory. However, if we use the pointer
 * obtained from z[*]_usable() family functions, there is no need for this step. */
#define zmalloc_usable_size(p) zmalloc_size(p)

/* derived from https://github.com/systemd/systemd/pull/25688
 * We use zmalloc_usable_size() everywhere to use memory blocks, but that is an abuse since the
 * malloc_usable_size() isn't meant for this kind of use, it is for diagnostics only. That is also why the
 * behavior is flaky when built with _FORTIFY_SOURCE, the compiler can sense that we reach outside
 * the allocated block and SIGABRT.
 * We use a dummy allocator function to tell the compiler that the new size of ptr is newsize.
 * The implementation returns the pointer as is; the only reason for its existence is as a conduit for the
 * alloc_size attribute. This cannot be a static inline because gcc then loses the attributes on the function.
 * See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=96503 */
__attribute__((alloc_size(2),noinline)) void *extend_to_usable(void *ptr, size_t size);
#endif

int get_proc_stat_ll(int i, long long *res);

#ifdef REDIS_TEST
int zmalloc_test(int argc, char **argv, int flags);
#endif

#endif /* __ZMALLOC_H */
