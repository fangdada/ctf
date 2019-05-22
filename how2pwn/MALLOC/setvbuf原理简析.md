> 环境：glibc2.23

&emsp;&emsp;<font size=2>对于\_IO_FILE，我们再分析最后一个函数：setvbuf，这个是用来设置标准输入输出或者错误输出的临时缓冲区的，在CTF中经常能看到`setvbuf(stdout,0,2,0);`这样的代码，效果相当于不会为\_IO_2_1_stdout_结构体分配堆块，那么这样就能保持堆区的干净来留给我们去pwn了，那么我们一步一步来分析这一行代码到底做了什么吧，首先来看看这一行代码执行前我们的\_IO_2_1_stdout\_（这就是setvbuf的第一个参数stdout，其实就是这个结构体）：</font></br>

```
pwndbg> p _IO_2_1_stdin_
$6 = {
  file = {
    _flags = -72540022, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = -1, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
pwndbg> 
```

&emsp;&emsp;<font size=2>然后常规，我们直接从setvbuf的源码开始看起：</font></br>

```C
weak_alias (_IO_setvbuf, setvbuf)
#define _IONBF 2		/* No buffering.  */

int
_IO_setvbuf (_IO_FILE *fp, char *buf, int mode, _IO_size_t size)
{
  int result;
  CHECK_FILE (fp, EOF);
  _IO_acquire_lock (fp);
  switch (mode)
    {
      //...
      case _IONBF:
        fp->_IO_file_flags &= ~_IO_LINE_BUF;
        fp->_IO_file_flags |= _IO_UNBUFFERED;
        buf = NULL;
        size = 0;
        break;
      //...
    }
  result = _IO_SETBUF (fp, buf, size) == NULL ? EOF : 0;
```

&emsp;&emsp;<font size=2>switch代码块中先对fp->_flags的标志位进行了一些设置，然后调用了\_IO_SETBUF，其真正名称是\_IO_new_file_setbuf：</font></br>

```C
_IO_FILE *
_IO_new_file_setbuf (_IO_FILE *fp, char *p, _IO_ssize_t len)
{
  if (_IO_default_setbuf (fp, p, len) == NULL)
    return NULL;

```

&emsp;&emsp;<font size=2>内部又立马调用了\_IO_default_setbuf：</font></br>

```C
_IO_FILE *
_IO_default_setbuf (_IO_FILE *fp, char *p, _IO_ssize_t len)
{
    if (_IO_SYNC (fp) == EOF)
        return NULL;
```

&emsp;&emsp;<font size=2>进去又调用了vtable的\_IO_SYNC，其实是_IO_new_file_sync：</font></br>

```C
int
_IO_new_file_sync (_IO_FILE *fp)
{
  _IO_ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    //...
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
      //...
    }
  if (retval != EOF)
    //...
  return retval;
}
libc_hidden_ver (_IO_new_file_sync, _IO_file_sync)

```

&emsp;&emsp;<font size=2>这个函数相当于什么都没做，返回到了\_IO_default_setbuf，返回值为0：</font></br>

```C


    if (p == NULL || len == 0)
      {
        fp->_flags |= _IO_UNBUFFERED;
        _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
      }
    else
      {
        //...
      }
```

&emsp;&emsp;<font size=2>len就是\_IO_default_setbuf的参数，这个参数是从setvbuf一层一层传下来的，是0，所以满足了if的条件，fp->_flags的\_IO_UNBUFFERED标志位被置位，然后调用了\_IO_setb：</font></br>

```C
void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    //...
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
```

&emsp;&emsp;<font size=2>在这里f->\_IO_buf_base被设置为了f->\_shortbuf的地址，buf_end设置为了shortbuf+1，同样设置了一下flags，然后返回了，控制流回到_IO_new_file_setbuf：</font></br>

```C
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
        (fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))

  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);

  return fp;
}
```

&emsp;&emsp;<font size=2>在这里设置了fp的\_IO_write_\*和\_IO_read\_\*，完了之后\_IO_2_1_stdin\_状态如下：</font></br>

```
pwndbg> p _IO_2_1_stdin_
$10 = {
  file = {
    _flags = -72540021, 
    _IO_read_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_read_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_read_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_buf_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_buf_end = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = -1, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
pwndbg> 
```

&emsp;&emsp;<font size=2>函数的剩余部分就是释放锁了，这里就不描述了：</font></br>

```C
unlock_return:
  _IO_release_lock (fp);
  return result;
}
```

&emsp;&emsp;<font size=2>同样的方式设置了\_IO_2_1_stdout_结构体，然后我们看看setvbuf后，puts一串helloworld会是什么样的流程，我们再来看一次puts：</font></br>

```C
weak_alias (_IO_puts, puts)
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
#  define _IO_fwide(__fp, __mode) \
  ({ int __result = (__mode);                                                 \
     if (__result < 0 && ! _IO_fwide_maybe_incompatible)                      \
       {                                                                      \
         if ((__fp)->_mode == 0)                                              \
           /* We know that all we have to do is to set the flag.  */          \
           (__fp)->_mode = -1;                                                \
         __result = (__fp)->_mode;                                            \
       }                                                                      \
     else if (__builtin_constant_p (__mode) && (__mode) == 0)                 \
       //...
     else                                                                     \
       //...
     __result; })
# endif

int
_IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
```

&emsp;&emsp;<font size=2>像\_IO_stdout这种程序一开始就初始化了的结构，其vtable肯定不为0，\_IO_fwide就是把\_mode设置为了-1，然后就调用了\_IO_sputn，其真正名称是_IO_new_file_xsputn：</font></br>

```C
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define _IO_LINE_BUF 0x200
#define _IO_CURRENTLY_PUTTING 0x800

_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    //...
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      //...
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    //...

  /* Then fill the buffer. */
  if (count > 0)
    {
      //...
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        //...

```

&emsp;&emsp;<font size=2>因为之前setvbuf中取消了\_IO_LINE_BUF标志位，所以第二个if中的标志位判断肯定不满足，一直往下调用了\_IO_OVERFLOW，真实调用为_IO_new_file_overflow：</font></br>

```C
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      //...
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
        {
          //...
        }
      /* Otherwise must be currently reading.
         If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
         logically slide the buffer forwards one block (by setting the
         read pointers to all point at the beginning of the block).  This
         makes room for subsequent output.
         Otherwise, set the read pointers to _IO_read_end (leaving that
         alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
        {
          //...
        }
      if (f->_IO_read_ptr == f->_IO_buf_end)
        //...
      f->_IO_write_ptr = f->_IO_read_ptr; 
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
        f->_IO_write_end = f->_IO_write_ptr;
    }   
    if (ch == EOF)
      return _IO_do_write (f, f->_IO_write_base,
                         f->_IO_write_ptr - f->_IO_write_base);
```

&emsp;&emsp;<font size=2>因为调用overflow的时候ch传参为EOF，所以这里返回的时候调用了\_IO_do_write，在看函数之前我们再来看一眼\_IO_2_1_stdout_：</font></br>

```C
pwndbg> p _IO_2_1_stdout_
$9 = {
  file = {
    _flags = -72537977, 
    _IO_read_ptr = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_read_end = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_read_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_write_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_write_ptr = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_write_end = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_buf_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "", 
    _IO_buf_end = 0x7ffff7dd26a4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7dd18e0 <_IO_2_1_stdin_>, 
    _fileno = 1, 
    _flags2 = 0, 
    _old_offset = -1, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7ffff7dd3780 <_IO_stdfile_1_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd17a0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = -1, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
pwndbg> 
```

&emsp;&emsp;<font size=2>函数如下：</font></br>

```C
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
          || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```

&emsp;&emsp;<font size=2>因为`to_do=_IO_write_ptr-_IO_write_base=0`，因此直接返回0了，控制流回到了_IO_new_file_xsputn：</font></br>

```C
      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
        {
          count = new_do_write (f, s, do_write);
```

&emsp;&emsp;<font size=2>block_size为1，do_write就为to_do也就是待输出的字符串的长度，然后就进入new_do_write，其实为\_IO_new_file_write：</font></br>

```C
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      _IO_ssize_t count = (__builtin_expect (f->_flags2
                                             & _IO_FLAGS2_NOTCANCEL, 0)
                           ? write_not_cancel (f->_fileno, data, to_do)
                           : write (f->_fileno, data, to_do));
      if (count < 0)
        {
          f->_flags |= _IO_ERR_SEEN;
          break;
        }
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```

&emsp;&emsp;<font size=2>这个函数我们已经分析过了，其调用了系统函数write，最后返回n（字符串长度），最后剩余代码如下：</font></br>

```C
          count = new_do_write (f, s, do_write);
          to_do -= count;
          if (count < do_write)
            //...
        }

      /* Now write out the remainder.  Normally, this will fit in the
         buffer, but it's somewhat messier for line-buffered files,
         so we let _IO_default_xsputn handle the general case. */
      if (to_do)
        //...
    }
  return n - to_do;
}

```

&emsp;&emsp;<font size=2>返回了输出的字符串长度到了puts：</font></br>

```C
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}

```

&emsp;&emsp;<font size=2>\_IO_putc_unlocked还输出了一个换行符，但这已经不值得我们去研究了，所以总结一下就是：</font></br>

&emsp;&emsp;<font size=2>setvbuf设置了\_IO_2_1_stdout_结构体中的flags和一系列\_IO_read\_\*和\_IO_write\_\*等成员，然后下一次puts的时候会直接根据字符串地址进行输出而不会先把字符串拷贝到临时缓冲区里去。</font></br>