&emsp;&emsp;<font size=2>free函数的讲解我们同样以hello,world程序开始，有如下代码：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
	free(malloc(0x100));

	return 0;
}
```

&emsp;&emsp;<font size=2>我们之前已经分析过了第一次使用`malloc(0x100);`后的堆情况（main_arena被初始化，sbrk分配top chunk后被切割），那么如果我们对仅剩的这一个堆块直接调用free会怎么样呢？来直接从\_\_libc_free开始看：</font></br>

```C
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
#define IS_MMAPPED 0x2

void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      //...
    }
  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);
}

```

&emsp;&emsp;<font size=2>在函数的开头直接检查了\_\_free_hook区域，但free不像malloc，第一次调用的时候\_\_free_hook里是空的，因此继续往下执行。mem为free的参数，也就是堆块指针，这个指针指向的是堆块的fd区域（想想malloc返回的是什么），mem2chunk宏就是重新把指针计算回了堆头，chunk_is_mmaped检查了size中的mmap标志位，显然我们的堆块并不是mmap得到的。</font></br>

&emsp;&emsp;<font size=2>然后常规操作，先获取main_arena，然后传参调用_int_free函数：</font></br>

```C
#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      //...
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      //...
    }

  check_inuse_chunk(av, p);
  
    if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
        If TRIM_FASTBINS set, don't place chunks
        bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {
					//...
    }
```

&emsp;&emsp;<font size=2>check_inuse_chunk函数内部多是对p（释放的堆块）的下一个堆块进行了一些断言检查，主要是下一个堆块的pre_inuse位必须置位，没有很多对堆块的操作，然后因为我们释放的堆块大小是大于fastbin大小的，所以if条件不满足，我们继续往下看：</font></br>

```C
  #define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      {
        errstr = "double free or corruption (top)";
        goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
                          && (char *) nextchunk
                          >= ((char *) av->top + chunksize(av->top)), 0))
      {
        errstr = "double free or corruption (out)";
        goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
        errstr = "double free or corruption (!prev)";
        goto errout;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
        || __builtin_expect (nextsize >= av->system_mem, 0))
      {
        errstr = "free(): invalid next size (normal)";
        goto errout;
      }
  
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

```

&emsp;&emsp;<font size=2>这里也是一些检查，看errstr就能看出个大概来，无非就是检查下一个堆块的prev_inuse以及free的是否是top或者下一个堆块的size检查，目的是确保free的堆块是否合法，free的检查可以说是非常多了，`free_perturb`跟`alloc_perturb`差不多，啥都不做，继续：</font></br>

```C
    /* consolidate backward */
    if (!prev_inuse(p)) {
      //...
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      //...
    }
    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```

&emsp;&emsp;<font size=2>因为在我们的情况下，nextchunk就是top堆块，所以进入else块里，合并的操作非常简单，直接修改top堆块，然后重新设置一下top头覆盖原来的堆块就行了。结束了:D</font></br>

&emsp;&emsp;<font size=2>largebin也是这种情况，但有一个不同就是fastbin，fastbin不会立马被合并到top堆块里，假设有这样的代码`free(malloc(0x20));`情况就会不太一样，我们重新分析一下，这次直接从_int_free开始看起，跳过前面的常规检查：</font></br>

```C
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
        If TRIM_FASTBINS set, don't place chunks
        bordering top into fastbins
      */
      //...
#endif
      ) {
          if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
        || __builtin_expect (chunksize (chunk_at_offset (p, size))
                             >= av->system_mem, 0))
          {
            //...
          }
    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
```

&emsp;&emsp;<font size=2>我们就从这个set_fastbinchunks开始看，这都是之前的堆块没有的，相关定义如下：</font></br>

```C
#define set_fastchunks(M)      catomic_and (&(M)->flags, ~FASTCHUNKS_BIT)
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
```

&emsp;&emsp;<font size=2>catomic_and其实就是原子操作，顾名思义就行了，将main_arena的flags中清空了FASTCHUNKS_BIT标志位，然后计算得到size相应的索引后又根据索引取得fastbinY的地址，然后定义了一个old取得了fb指针的值（其实就是fastbinY数组里的值，如果多free几个fastbin就会发现这个值是最后一次free的fastbin堆块的地址），继续往下看：</font></br>

```C
    do
      {
        /* Check that the top of the bin is not the record we are going to add
           (i.e., double free).  */
        if (__builtin_expect (old == p, 0))
          {
            errstr = "double free or corruption (fasttop)";
            goto errout;
          }
        /* Check that size of fastbin chunk at the top is the same as
           size of the chunk that we are adding.  We can dereference OLD
           only if we have the lock, otherwise it might have already been
           deallocated.  See use of OLD_IDX below for the actual check.  */
        if (have_lock && old != NULL)
          old_idx = fastbin_index(chunksize(old));
        p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
        errstr = "invalid fastbin entry (free)";
        goto errout;
      }
  }
```

&emsp;&emsp;<font size=2>大名鼎鼎的double free听说过没？第一个if就是这个fastbin double free的检查了，可以看出来检查很简单，只检查了free的堆块是否是fastbinY中目前记录的值，也就是说，只有连续free两次同一个fastbin才会触发这个错误，绕过很简单，两次free的中间free一次其他的fastbin就能绕过了。</font></br>

&emsp;&emsp;<font size=2>这些利用技巧我会在其他地方总结，那么这个do while循环最后做的就是把刚释放的堆块的fd放上fastbinY里的相关索引的数据，第一次释放的话那就是0，完了之后会把fastbinY那里设置为堆块的地址，释放一个fastbin的效果如下：</font></br>

```
pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000031
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000031
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000020fa1
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
pwndbg> p main_arena
$1 = {
  mutex = 0, 
  flags = 0, 
  fastbinsY = {0x0, 0x602000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x602060, 
  last_remainder = 0x0, 

```

&emsp;&emsp;<font size=2>如果连续申请两个0x20，并按照顺序释放他们的话效果如下，可以推出来：</font></br>

```
pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000031
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000031
0x602040:	0x0000000000602000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000020fa1
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
pwndbg> p main_arena
$2 = {
  mutex = 0, 
  flags = 0, 
  fastbinsY = {0x0, 0x602030, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x602060, 
```

&emsp;&emsp;<font size=2>与我们分析出来的预期结果一致，连续释放同一个堆块double free报错效果如下：</font></br>

```
➜  temp ./test 
*** Error in `./test': double free or corruption (fasttop): 0x0000000000a4e010 ***
======= Backtrace: =========

```

