&emsp;&emsp;<font size=2>前三节我们已经分析完了对于第一次申请smallbin程序所做的一切工作，那么接下来根据hello,world程序，再分配一个0x20的fastbin会发生什么呢？我们还是从\_\_libc_malloc开始看起：</font></br>

```C
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
```

&emsp;&emsp;<font size=2>这一次，\_\_malloc_hook里已经没有函数需要调用了，因此是0。同样的arena_get取得main_arena地址赋予ar_ptr，然后调用了_int_malloc这个主要分配函数：</font></br>

```C
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      //...
    }

```

&emsp;&emsp;<font size=2>首先还是通过`checked_request2size`这个宏把申请的size转化为实际申请的size。接下来是fastbin链表查询：</font></br>

```C
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          //...
        }
    }
```

&emsp;&emsp;<font size=2>因为经过第一个堆块的申请，此时`get_max_fast()`获取的地址已经有了数据，就是0x80。我们申请的大小为0x20，nb就会是0x30，接下来是涉及的一些宏定义：</font></br>

```C
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

&emsp;&emsp;<font size=2>首先根据size求得index，因为chunk的大小最少为0x20，所以`(0x20>>4)-2`就是0，正好对应fastbinY数组里的最小堆块的地址，然后是一个do while循环，如果fastbinY里有堆块的话，循环结束后victim指向的应当是链表中最后一个堆块（通过fd指针查找），但是我们的fastbinY数组还未初始化，因此第一次就遇到break退出了，下面的if条件也不成立，因此继续往下执行：</font></br>

```C
#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)		//0

    if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          //...
        }

    }
  else
    {
      //...
    }
```

&emsp;&emsp;<font size=2>因为nb（0x30）在smallbin的范围内，而且经过第一个堆块的申请，bins链表已经被初始化，所以if中`last(bin)!=bin`无法满足，跳出if，继续往下看：</font></br>

```C
#define unsorted_chunks(M)          (bin_at (M, 1))

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          //...
        }
      if (!in_smallbin_range (nb))
        {
          //...
        }
      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);



```

&emsp;&emsp;<font size=2>与第一次分配堆块类似，binmap都是0，所以`bit>map`条件必定满足，do while四次循环后跳入use_top：</font></br>

```C
   use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
```

&emsp;&emsp;<font size=2>top之前已经经过设置，是一个很大的值，我们申请的nb+MINSIZE应该为0x50，所以肯定是可以进入if执行的。接下来的操作非常简单，只需要把top的size设置一下，切割出来就能用了，我们很快就得到了一个fastbin，而largebin的方式我猜测也差不多，所以malloc的部分就讲完了，所以这一个系列完结了:D</font></br>