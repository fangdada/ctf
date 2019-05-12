&emsp;&emsp;<font size=2>在这一节我们将完成第一节中我们所见所得的原理分析。话不多说，直接上源码：</font></br>

```C
#define unsorted_chunks(M)          (bin_at (M, 1)) 
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))                           \
             - offsetof (struct malloc_chunk, fd))
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)			//0x20
#define BINMAPSIZE       (NBINS / BITSPERMAP)			//4
#define NBINS             128

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))


for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          //...
        }
      if (!in_smallbin_range (nb))
        {
          //..
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

&emsp;&emsp;<font size=2>因为在这里我们是第一次分配堆块，所以while的判断无法命中，后面的`!in_smallbin_range`也无法满足（因为我们申请的就是smallbin大小），因此往后就是binmap的操作了，我分析了下每一个binmap block可以"照顾"16个堆块，由`(1<<5)/2=0x10`得出，因此对于bins这个64个堆块（相当于128个索引）大小的堆块数组，BINMAPSIZE为4正好够用，与程序计算得出的相符合。因为我们的binmap为空，所以`bit>map`是肯定的（注意bit在这里更像是一个索引，不是0）。接下来的do while循环中，因为我们的binmap为空，所以会循环四次最后goto到了use_top处：</font></br>

```C
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

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
          //...
        }
      else if (have_fastchunks (av))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}

```

&emsp;&emsp;<font size=2>显然top chunk还未被分配，还只是被初始化为了其在main_arena自身的地址，因此size为0，因此不满足if条件判断，而fastchunks当然也没有，所以最终来到了sysmalloc初始化堆区：</font></br>

```C
/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */

static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;


  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
          && (mp_.n_mmaps < mp_.n_mmaps_max)))
    {
      //...
    }
  if (av == NULL)
    return 0;

  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);

  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));


  if (av != &main_arena)
    {
      //...
    }
  
  
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

```

&emsp;&emsp;<font size=2>因为top chunk的大小为0（还未初始化），所以old_top为top在main_arena中的地址，old_size为0，最终old_end经过计算仍然为top的地址。因为av就是main_arena，因此if条件不满足，进入else：</font></br>

```C
#define NONCONTIGUOUS_BIT     (2U)
#define contiguous(M)          (((M)->flags & NONCONTIGUOUS_BIT) == 0)
//include/libc-internal.h
#define ALIGN_UP(base, size)    ALIGN_DOWN ((base) + (size) - 1, (size))
#define ALIGN_DOWN(base, size)  ((base) & -((__typeof__ (base)) (size)))

else     /* av == main_arena */
  { 
      /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */
      if (contiguous (av))
        size -= old_size;

      /*
         Round to a multiple of page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */
      size = ALIGN_UP (size, pagesize);
    
      if (size > 0)
      {
        brk = (char *) (MORECORE (size));
        LIBC_PROBE (memory_sbrk_more, 2, brk, size);
      }

```

&emsp;&emsp;<font size=2>我们申请的大小为0x100，因此nb为0x110，size为`nb+MINSIZE=0x130`，pagesize在这里为0x20000，由sysmalloc函数开头的`  size_t pagesize = GLRO (dl_pagesize);`得到，\__typeof__这个有必要说明一下，这是一个编译拓展，非常类似python里的type函数，只是GCC里这个可以这样用：`int a;typeof(a) b;`，这样做相当于`int a;int b;`因此ALIGN_UP最终返回的大小为0x21000。然后调用了\_\_morecore函数，其实际上是\_\_default_morecore：</font></br>

```C
# define __sbrk  sbrk

void *
__default_morecore (ptrdiff_t increment)
{
  void *result = (void *) __sbrk (increment);
  if (result == (void *) -1)
    return NULL;

  return result;
}
```

&emsp;&emsp;<font size=2>可以看到最终调用了sbrk函数，这是一个很眼熟的函数，Linux的终极内存分配器2333，其参数就是之前计算得到的0x21000。因为这已经很底层了，再深入一步你都能看到SYSCALL了，所以不细扒了，只要知道其返回值就是得到的堆区的首地址就行了（堆区就是在这个时候出现）。然后控制流回到了sysmalloc，继续往下看：</font></br>

```C
#define MORECORE_FAILURE 0

      if (brk != (char *) (MORECORE_FAILURE))
        {
          /* Call the `morecore' hook if necessary.  */
          void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
          if (__builtin_expect (hook != NULL, 0))
            (*hook)();
        }
      else
        {
          //...
        }
```

&emsp;&emsp;<font size=2>brk就是返回的堆区的首地址，在调试器下应当为0x602000，MORECORE_FAILURE就是0。所以if其实就是检查sbrk分配内存是否成功（失败会返回0，因此正好进入else），在这里sbrk成功了，所以进入if内部，检查\__after_morecore_hook区域是否有函数，有的话就用hook调用之（新思路？），吐槽一句这个函数可真长啊真累，主要是编译器优化的太厉害，控制流乱七八糟的，gdb跟踪的时候要仔细看。不过最后两个大if了，继续看：</font></br>

```C
      if (brk != (char *) (MORECORE_FAILURE))
        {
          if (mp_.sbrk_base == 0)
            mp_.sbrk_base = brk;
          av->system_mem += size;
        
          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            //...

          else if (contiguous (av) && old_size && brk < old_end)
            {
              //...
            }

          /*
             Otherwise, make adjustments:

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* handle contiguous cases */
              if (contiguous (av))
                {
                  //...
                }
              else
              {
                if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                else
                  {
                    front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                    if (front_misalign > 0)
                      {
                        /*
                           Skip over some bytes to arrive at an aligned position.
                           We don't need to specially mark these wasted front bytes.
                           They will never be accessed anyway because
                           prev_inuse of av->top (and any chunk created from its start)
                           is always true after initialization.
                         */

                        aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                      }
                  }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                  {
                    snd_brk = (char *) (MORECORE (0));
                  }
              }
            

```

&emsp;&emsp;<font size=2>显然控制流会进入这个if，mp_.sbrk_base在这个时候被设置为了sbrk返回的堆区首地址，size为之前分析的0x21000，av->system_mem为0，所以现在被设置为了0x21000。随后会再一次调用MORECORE，而MORECORE实际上就是\_\_morecore，最终调用了\_\_sbrk，而这一次返回了堆区的末地址。所以snd_brk就是堆区的末地址，在调试器里面一般为0x623000。最后一个大if：</font></br>

```C
#define set_head(p, s)       ((p)->size = (s))

                if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;

                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)
                    { 
                      //...
                    }
                 }  
              } 
         }
     }

  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state (av);

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
}

```

&emsp;&emsp;<font size=2>correction在这里实际上为0，所以在这里设置了top堆块的地址（堆区的首地址），然后设置了top堆块的`pre_inuse`位，最终size上为0x21001，但还没完呢，显然目前堆区的大小是大于我们申请的大小的，还要减去我们申请的堆块大小0x110，所以还要重新设置top堆块的head和申请的堆块的head，这个时候堆区的内存快照已经变为了我们在第一节看到的样子了！_int_malloc也到了末尾了：</font></br>

```C
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}

```

&emsp;&emsp;<font size=2>p就是从sysmalloc返回的堆块，也就是我们的一手看大的堆块，最后会调用一下alloc_perturb函数：</font></br>

```C
static void
alloc_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
    memset (p, perturb_byte ^ 0xff, n);
}
```

&emsp;&emsp;<font size=2>但是perturb_byte未定义所以函数直接返回了。这可能也是malloc返回的堆块会有use-after-free的原因吧2333，接下来控制流回到了\_\_libc_malloc：</font></br>

```C
  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```

&emsp;&emsp;<font size=2>然后就是对堆块进行一些最终检查后把堆块交到用户手上了。对`malloc(0x100);`的第一次调用分析完成了，内容有点多，剩下的我们下节再看。</font></br>