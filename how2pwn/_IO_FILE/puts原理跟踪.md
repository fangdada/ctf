## _IO_FILE | 对puts的一次简单跟踪分析

&emsp;&emsp;<font size=2>首先，我们来看如下最简单的输出代码：</font></br>

```C
#include <stdio.h>

int main()
{
	puts("hello,world");
	puts("end");
	return 0;
}

```

&emsp;&emsp;<font size=2>接下来我们就根据glibc2.23中的源码结合gdb跟踪完成这一分析，首先看`libio/ioputs.c`：</font></br>

```C
#include "libioP.h"
#include <string.h>
#include <limits.h>

int
_IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}

#ifdef weak_alias
weak_alias (_IO_puts, puts)
#endif

```

&emsp;&emsp;<font size=2>可以看到\_IO\_puts是puts的别名，\_IO\_puts其实就是`_IO_new_file_xsputn`，其他的其实跟输出没什么太多的关系，所以接下来我们开始逐步分析`_IO_new_file_xsputn`，这个函数接受参数strlen得到的str长度，str字符串和`_IO_2_1_stdout_`结构，源码开头：</font></br>

```C
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      //....
    }
    else if (f->_IO_write_end > f->_IO_write_ptr)
      //...

```

&emsp;&emsp;<font size=2>to_do就是puts参数中的字符串的长度，第一次调用puts（或者说，第一次stdout输出）时，f->\_flags为0xfbad2084，而`_IO_LINE_BUF | _IO_CURRENTLY_PUTTING`为0xa00，因此if内部不会得到执行，而f->\_IO_write_end和f->\_IO_write_ptr都为0，else if条件也不满足：</font></br>

```assembly
───────────────────────────────────────[ REGISTERS ]───────────────────────────────────────
 RAX  0xfbad2084
 RBX  0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
 RCX  0x5d4
 RDX  0xb
 RDI  0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
 RSI  0x4005d4 ◂— push   0x6f6c6c65 /* 'hello,world' */
 R8   0x7ffff7fda700 ◂— 0x7ffff7fda700
 R9   0x7ffff7de7ab0 (_dl_fini) ◂— push   rbp
 R10  0x194
 R11  0x7ffff7a7c690 (puts) ◂— push   r12
 R12  0xb
 R13  0x4005d4 ◂— push   0x6f6c6c65 /* 'hello,world' */
 R14  0x0
 R15  0x0
 RBP  0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
 RSP  0x7fffffffdbc0 —▸ 0x400526 (main) ◂— push   rbp
 RIP  0x7ffff7a86204 (_IO_file_xsputn+36) ◂— and    eax, 0xa00 /* '%' */
────────────────────────────────────────[ DISASM ]─────────────────────────────────────────
   0x7ffff7a861f7 <_IO_file_xsputn+23>    push   rbx
   0x7ffff7a861f8 <_IO_file_xsputn+24>    mov    r12, rdx
   0x7ffff7a861fb <_IO_file_xsputn+27>    mov    rbx, rdi
   0x7ffff7a861fe <_IO_file_xsputn+30>    sub    rsp, 8
   0x7ffff7a86202 <_IO_file_xsputn+34>    mov    eax, dword ptr [rdi]
 ► 0x7ffff7a86204 <_IO_file_xsputn+36>    and    eax, 0xa00
   0x7ffff7a86209 <_IO_file_xsputn+41>    cmp    eax, 0xa00
   0x7ffff7a8620e <_IO_file_xsputn+46>    je     _IO_file_xsputn+240 <0x7ffff7a862d0>
 
   0x7ffff7a86214 <_IO_file_xsputn+52>    mov    rdx, qword ptr [rdi + 0x30]
   0x7ffff7a86218 <_IO_file_xsputn+56>    mov    rdi, qword ptr [rdi + 0x28]
   0x7ffff7a8621c <_IO_file_xsputn+60>    cmp    rdx, rdi

pwndbg> p _IO_2_1_stdout_
$1 = {
  file = {
    _flags = -72540028, 
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

```

&emsp;&emsp;<font size=2>接下来源码如下：</font></br>

```C
  /* Then fill the buffer. */
  if (count > 0)
    { 
      //....
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        return to_do == 0 ? EOF : n - to_do;
//....

```

&emsp;&emsp;<font size=2>由于count初始化为0，因此第一个if不执行，to_do为"hello,world"的长度为0xb，因此接下来控制流到达了\_IO_OVERFLOW，\_IO_OVERFLOW又是\_IO_new_file_overflow，因此调用之，\_IO_new_file_overflow源码开头如下：</font></br>

```C
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      //....
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
        {
          _IO_doallocbuf (f);
          _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
        }
//....
```

&emsp;&emsp;<font size=2>\_IO_NO_WRITES为8，显然0xfbad2084不满足，而f->\_IO_write_base为0，因此控制流会进入\_IO_doallocbuf分配内存作为缓冲区：</font></br>

```C
void
_IO_doallocbuf (_IO_FILE *fp)
{
  if (fp->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED) || fp->_mode > 0)
    if (_IO_DOALLOCATE (fp) != EOF)
      return;
  _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
}
```

&emsp;&emsp;<font size=2>\_IO_UNBUFFERED为2，因此满足了if条件，进入\_IO_DOALLOCATE（其实为filedoalloc.c中的\_IO_file_doallocate分配内存，关键代码如下：</font></br>

```C
  p = malloc (size);
  if (__glibc_unlikely (p == NULL))
    return EOF;
  _IO_setb (fp, p, p + size, 1);
  return 1;
}
```

&emsp;&emsp;<font size=2>\_IO_setb源码为：</font></br>

```C
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
```

&emsp;&emsp;<font size=2>不难看出，其设置了\_IO_buf_base和\_IO_buf_end为堆的区间，并且取消了\_IO_USER_BUF的置位，最后控制流返回到了\_IO_file_overflow，调用了\_IO_setg，其把\_IO_read_base，ptr，end都设置为了堆块首地址：</font></br>

```C
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
        (fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
```

&emsp;&emsp;<font size=2>\_IO_file_overflow剩余部分的代码如下：</font></br>

```C
      if (f->_IO_read_ptr == f->_IO_buf_end)
        f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
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
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
                      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;     
  return (unsigned char) ch;
}
```

&emsp;&emsp;<font size=2>此时\_IO_read_ptr为堆区首地址，\_IO_buf_end为堆末地址，不满足相等条件。继续往下看则是对\_IO_write_ptr，base，end等的赋值，并对f->\_flags的\_IO_CURRENTLY_PUTTING进行了置位，由于传入的参数ch为EOF，所以控制流进入了\_IO_do_write：</font></br>

```C
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      //....
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```

&emsp;&emsp;<font size=2>此时传入的n为\_IO_write_ptr-\_IO_write_base为0，因此\_IO_new_file_write直接return 0。控制流回到了\_IO_new_file_xsputn：</font></br>

```C
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
        {
          //...
        }

      /* Now write out the remainder.  Normally, this will fit in the
         buffer, but it's somewhat messier for line-buffered files,
         so we let _IO_default_xsputn handle the general case. */
      if (to_do)
        to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```

&emsp;&emsp;<font size=2>返回后，block_size为0x400，do_write为0，to_do仍然为0xb（"hello,world"的长度），因此，\_IO_default_xsputn被调用了：</font></br>

```C
_IO_size_t
_IO_default_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (char *) data;
  _IO_size_t more = n;
  if (more <= 0)
    return 0;
  for (;;)
    {
      if (f->_IO_write_ptr < f->_IO_write_end)
      {
//......
      }
      if (more == 0 || _IO_OVERFLOW (f, (unsigned char) *s++) == EOF)
        break;
      more--;
    }
  return n - more;
}
```

&emsp;&emsp;<font size=2>由于此时\_IO_write_ptr=\_IO_write_end，所以第一个if不满足，再一次调用了\_IO_new_file_overflow：</font></br>

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
      //...
    }
    if (ch == EOF)
      //...
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    //...
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
                      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}

```

&emsp;&emsp;<font size=2>这一次\_IO_new_file_overflow把传入的参数的字符串中的一个字节放入了\_IO_write_ptr所处的缓冲区中，然后不满足if判断，return  (unsigned char)ch返回到了\_IO_default_xsputn中：</font></br>

```C
  for (;;)
    {
      /* Space available. */ 
      if (f->_IO_write_ptr < f->_IO_write_end)
        {
          //...
        }
      if (more == 0 || _IO_OVERFLOW (f, (unsigned char) *s++) == EOF)
        break;
      more--;
    }

```

&emsp;&emsp;<font size=2>\_IO_OVERFLOW返回的是ch，所以不会触发break，more自减1后重新循环再次调用了\_IO_OVERFLOW直到达到字符串末尾的换行符，这时if判断满足了，\_IO_do_write被调用，传入参数为f，f->\_IO_write_base和字符串长度：</font></br>

```C
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
          || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
```

&emsp;&emsp;<font size=2>其内部又以同样的参数调用了new_do_write：</font></br>

```C
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    //...
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      //...
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    //....
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
                       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

&emsp;&emsp;<font size=2>可以看到终于用\_IO_SYSWRITE输出了我们的字符串，然后将fp->\_IO_write_base,ptr,end和read_base,ptr,end全部置为了\_IO_buf_base，然后函数重新返回到了puts。至此，对第一次调用puts函数的过程就跟踪完毕了，接下来第二次调用就比较轻车熟路了：</font></br>

```C
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
        {
          const char *p;
          for (p = s + n; p > s; )
            {
              if (*--p == '\n')
                {
                  //...
                }
            }
        }
    }
```

&emsp;&emsp;<font size=2>第二次调用puts时，f->\_flags为0xfbad2a84，满足if中的两个条件，因此count被赋值为0x400，而且此处可能因为只有一个字符串，因此for循环中的if条件不会被满足，继续往下看：</font></br>

```C
  if (count > 0)
    {
      if (count > to_do)
        count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count);
      f->_IO_write_ptr += count;
#endif
      s += count;
      to_do -= count;
    }
```

&emsp;&emsp;<font size=2>count之前经过计算为堆区大小（0x400），因此count被赋值为to_do（也就是"end"字符串的长度3）后调用了\__memcpy，在f->\_IO_write_ptr处放入了"end"，s加上count长度后为字符串末尾，to_do减去count后为0，不满足后续的if条件，因此\_IO_new_file_overflow函数直接返回：</font></br>

```C
  if (to_do + must_flush > 0)
    {
      //...
    }
  return n - to_do;
}
```

&emsp;&emsp;<font size=2>这一次直接回到了puts函数内部，我们再来看一下puts函数的源码：</font></br>

```C
int
_IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}
```

&emsp;&emsp;<font size=2>\_IO_sputn的返回值为len，满足。然后调用了\_IO_putc_unlocked，其定义如下：</font></br>

```C
#define _IO_putc_unlocked(_ch, _fp) \
   (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) \
    ? __overflow (_fp, (unsigned char) (_ch)) \
    : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```

&emsp;&emsp;<font size=2>显然fp->\_IO_wirte_ptr是大于fp->\_IO_write_end的，所以\_\_overflow得以执行，而\_\_overflow事实上就是\_IO_new_file_overflow，此时流程如下：</font></br>

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
      //...
    }
  if (ch == EOF)
    //...
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    //...
  *f->_IO_write_ptr++ = ch;
```

&emsp;&emsp;<font size=2>传入的参数ch为换行符，因此相当于在"end"字符串末尾加上了一个换行符，继续往下看：</font></br>

```C
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
                      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;     
  return (unsigned char) ch;
}
```

&emsp;&emsp;<font size=2>虽然\_IO_UNBUFFERED不满足，但是f->\_flags的\_IO_LINE_BUF和ch为换行符的条件被满足，因此流程进入\_IO_do_write，之前说过其最终调用的是new_do_write:</font></br>

```C
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    //...
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      //...
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
                       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}

```

&emsp;&emsp;<font size=2>调用\_IO_SYSWRITE输出"end"后，重新置位f->\_IO_write_\*和\_IO_read\_\*等一系列结构后退出puts，完成整个输出过程。</font></br>

&emsp;&emsp;<font size=2>因此对puts函数的原理跟踪分析完成了，你也应该对整个流程有一个比较直观的认识了，下次有时间我可能再更新一下对\_IO_FILE的各种利用。</font></br>

