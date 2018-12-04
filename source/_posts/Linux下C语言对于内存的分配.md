---
title: Linux下关于C&C++的内存分配
author: 3703liu
tags: [C&C++]
categories: [编程语言]
date: 2018-11-28 22:03:00

---
# 0 引言 
&emsp;&emsp;最近在项目中碰到C和C++中内存分配导致程序出现错误的问题，对Linux内存管理一直想好好研究一下，看过一些简单的介绍。但一直不太明白，先从C语言的内存的管理和分配开始看吧，记录一下中间学到的东西。中间看到过一片[Hack the Virtual Memory: malloc, the heap & the program break](https://blog.holbertonschool.com/hack-the-virtual-memory-malloc-the-heap-the-program-break/)的文章，讲解的较为详细，也有具体的demo代码，对于内存的分配会有比较直观的理解。

---  
## 1.内存的分配
  ### 1.1 brk的分配方法
  ### 1.2 mmap的分配方法
## 2.内存的数据结构
  &emsp;&emsp;内存在申请的时候，实际所分配的长度要比所申请的字节要长，mallloc 分配内存的时候，所返回的地址之前的16个字节，用来记录内存分配的相关信息，前八个字节用来记录上一个chunk是否被deallocate的信息，随后的八个字节记录本次分配的chunk size，且最后的bit用来作为flag，标记上一个chunk在分配时的相关标记。从gnu的malloc源码中，可以看到flag共有一下三种：
   ```cpp
   /* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
   #define PREV_INUSE 0x1
   /* extract inuse bit of previous chunk */
   #define prev_inuse(p)       ((p)->mchunk_size & PREV_INUSE)
   /* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
   #define IS_MMAPPED 0x2
   /* check for mmap()'ed chunk */
   #define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)
   /* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
   #define NON_MAIN_ARENA 0x4
   /* Check for chunk from main arena.  */
   #define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)
   /* Mark a chunk as not being on the main arena.  */
   #define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)
   ```
&emsp;&emsp;可以看到标记有三种，PREV_INUSE标记上个chunk是否INUSE，IS_MMAPPED标记当前chunk是否有mmap所分配的，还有一个NON_MAIN_ARENA，从注释看是标记当前chunk是否由非主分区分配，尚为明白其用意。
## 3.内存的释放
 &emsp;&emsp;内存的释放C语言在释放内存的时候会对内存作check，内存检测出现问题的时候，会调用_libc_message,进而调用abort终止进程。对于内存的检查是比较底层的东西了，记录一下目前所了解到的相关内容。内存释放的时候会调用__libc_free (void *mem),相关的源码可以从[ malloc.c ](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html)中可以查看，大致过程为获取chunk指针，然后检测chunk是否为mmapped，如果是的话调整阈值，释放指针，如何调整阈值还不清楚，其后则是调用_int_free。

&emsp;&emsp;_int_free函数源码较长，目前对函数的流程理解如下：
 * 检查chunk指针地址是否超过了可分配的内存空间的上限，以及内存是否对齐
 ```c
 /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");
 ```
 * 中间牵涉到fastbin操作，目前尚不明白
 ```c
  unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);
    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = fastbin_push_entry (fb, p);
 ```
 * 检查下个chunk是否已经为top block或者越过了av->top的边界(top尚不清楚具体含义，目前理解为内存页的最后一个chunk)
 ```c
  /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
                          && (char *) nextchunk
                          >= ((char *) av->top + chunksize(av->top)), 0))
        malloc_printerr ("double free or corruption (out)");
 ```
* 根据下个chunk检查当前chunk INUSE的标记
```c
/* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");
```
* 检查下个chunk的长度
```c
  nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
        || __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)")
```
* 如果上个chunk没有在使用，将当前chunk与上个chunk合并，这里挪动了chunk_ptr
```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```
* 清除下个chunk INUSE的标记与下个chunk合并，较为复杂，尚未看明白
* 如果是mmap方式申请的内存，调用 munmap_chunk进行释放。



  


 
  