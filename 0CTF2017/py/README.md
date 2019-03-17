# 0CTF2017 py

## Author: fanda

参考原文：https://0xd13a.github.io/ctfs/0ctf2017/py/

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题是一个.pyc文件的逆向，这题我们得到了一个entrypted_flag文件和一个pyc，第一次做这样的题肯定是一头雾水，但是逆向新鲜事物总是充满乐趣的2333，类似elf文件，pyc文件也是由一系列格式组成的一个“可执行文件”。那么pyc格式文件的参考资料是什么呢?我先放这，可以先不看，我下面会慢慢讲解：[python dis模块](https://docs.python.org/2.7/library/dis.html#python-bytecode-instructions),[机器码定义](https://svn.python.org/projects/python/trunk/Lib/opcode.py),[pyc格式](https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html)。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>或许有人想到有一个叫[python-uncompyle6](https://github.com/rocky/python-uncompyle6)的GitHub里的可以直接把pyc反编译成近似源代码的工具，但是这题让大家失望了：</font></br>

```shell
➜  Desktop uncompyle6 crypt.pyc 
# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.15rc1 (default, Nov 12 2018, 14:31:15) 
# [GCC 7.3.0]
# Embedded file name: /Users/hen/Lab/0CTF/py/crypt.py
# Compiled at: 2017-01-06 14:08:38
Traceback (most recent call last):
  File "/usr/local/bin/uncompyle6", line 11, in <module>
    load_entry_point('uncompyle6==3.2.5', 'console_scripts', 'uncompyle6')()
  File "build/bdist.linux-x86_64/egg/uncompyle6/bin/uncompile.py", line 181, in main_bin
  File "build/bdist.linux-x86_64/egg/uncompyle6/main.py", line 231, in main
  File "build/bdist.linux-x86_64/egg/uncompyle6/main.py", line 147, in decompile_file
  File "build/bdist.linux-x86_64/egg/uncompyle6/main.py", line 115, in decompile
  File "build/bdist.linux-x86_64/egg/uncompyle6/semantics/pysource.py", line 2284, in code_deparse
  File "build/bdist.linux-x86_64/egg/uncompyle6/scanners/scanner2.py", line 321, in ingest
IndexError: tuple index out of range
➜  Desktop  
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题的pyc结构被故意修改过，而且内部机器码也被混淆过，不能直接uncompyle6直接反编译了（常规操作。怀疑是工具问题的自己写个test.py试一下就知道了2333。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们老老实实从pyc结构开始学起吧，我们首先要从python的dis模块上手，看如下代码：</font></br>

```python
In [1]: def func(a):
   ...:     return a+1
   ...: 

In [2]: import dis

In [3]: dis.dis(func)
  2           0 LOAD_FAST                0 (a)
              3 LOAD_CONST               1 (1)
              6 BINARY_ADD          
              7 RETURN_VALUE        

In [4]: 
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>根据上面我发的[机器码定义](https://svn.python.org/projects/python/trunk/Lib/opcode.py)的资料，LOAD_FAST的机器码是124，LOAD_CONST是100，BINARY_ADD是23，RETURN_VLALUE是83，而LOAD_*的机器码是三字节大小的，要加上操作数，所以这一串机器码应当为（16进制）:7c00009401001753。我们用[pyc格式](https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html)里一位大牛写的脚本dec.py直接来编译这个函数：</font></br>

```shell
➜  Desktop python -m py_compile test.py
➜  Desktop ls
 angr-doc    ctf       dec.py   learning-angr               quest   test.py
 crypt.pyc   dec2.py   file    'Parallels Shared Folders'   temp    test.pyc
➜  Desktop python dec.py test.pyc     
magic 03f30d0a
moddate 96e78d5c (Sun Mar 17 14:22:14 2019)
code
   argcount 0
   nlocals 0
   stacksize 1
   flags 0040
   code 6400008400005a000064010053
  1           0 LOAD_CONST               0 (<code object func at 0x7f17286f2cb0, file "test.py", line 1>)
              3 MAKE_FUNCTION            0
              6 STORE_NAME               0 (func)
              9 LOAD_CONST               1 (None)
             12 RETURN_VALUE        
   consts
      code
         argcount 1
         nlocals 1
         stacksize 2
         flags 0043
         code 7c00006401001753
  2           0 LOAD_FAST                0 (a)
              3 LOAD_CONST               1 (1)
              6 BINARY_ADD          
              7 RETURN_VALUE        
         consts
            None
            1
         names ()
         varnames ('a',)
         freevars ()
         cellvars ()
         filename 'test.py'
         name 'func'
         firstlineno 1
         lnotab 0001
      None
   names ('func',)
   varnames ()
   freevars ()
   cellvars ()
   filename 'test.py'
   name '<module>'
   firstlineno 1
   lnotab 
➜  Desktop 
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>可以看到我们对机器码的推测是正确的，然后我们试着用升级版的dec2.py一下赛题：</font></br>

```shell
➜  py git:(master) ✗ python dec2.py crypt.pyc
  ## inspecting pyc file ##
filename:     crypt.pyc
magic number: 0x(03 f3 0d 0a)
timestamp:    1483682918 (Fri Jan  6 14:08:38 2017)
code
   co_argcount:        0
   co_cellvars:        ()
   co_filename:        '/Users/hen/Lab/0CTF/py/crypt.py'
   co_firstlineno:     1
   co_flags:           0x00040
   co_freevars:        ()
   co_lnotab:          '\x0c\x01\t\x08'
   co_name:            '<module>'
   co_names:           ('rotor', 'encrypt', 'decrypt')
   co_nlocals:         0
   co_stacksize:       2
   co_varnames:        ()
   co_consts
      0 -1
      1 None
      2 (code object)
         co_argcount:        1
         co_cellvars:        ()
         co_filename:        '/Users/hen/Lab/0CTF/py/crypt.py'
         co_firstlineno:     2
         co_flags:           0x00043
         co_freevars:        ()
         co_lnotab:          '\x00\x01\x06\x01\x06\x01\x06\x01.\x01\x0f\x01'
         co_name:            'encrypt'
         co_names:           ('rotor', 'newrotor', 'encrypt')
         co_nlocals:         6
         co_stacksize:       3
         co_varnames:        ('data', 'key_a', 'key_b', 'key_c', 'secret', 'rot')
         co_consts
            0 None
            1 '!@#$%^&*'
            2 'abcdefgh'
            3 '<>{}:"'
            4 4
            5 '|'
            6 2
            7 'EOF'
         co_code
            99 01 00 68 01 00 99 02 00 68 02 00 99 03 00 68
            03 00 61 01 00 99 04 00 46 99 05 00 27 61 02 00
            61 01 00 27 61 03 00 27 99 06 00 46 27 99 05 00
            27 61 02 00 99 06 00 46 27 99 07 00 27 68 04 00
            9b 00 00 60 01 00 61 04 00 83 01 00 68 05 00 61
            05 00 60 02 00 61 00 00 83 01 00 53
            disassembled:
Traceback (most recent call last):
  File "dec2.py", line 117, in <module>
    show_file(sys.argv[1])
  File "dec2.py", line 102, in show_file
    show_code(code, level=1)
  File "dec2.py", line 89, in show_code
    show_consts(code.co_consts, level=level+1)
  File "dec2.py", line 57, in show_consts
    show_code(obj, level=level+1)
  File "dec2.py", line 91, in show_code
    show_bytecode(code, level=level+1)
  File "dec2.py", line 68, in show_bytecode
    dis.disassemble(code)
  File "/usr/local/Cellar/python@2/2.7.15_1/Frameworks/Python.framework/Versions/2.7/lib/python2.7/dis.py", line 97, in disassemble
    print '(' + co.co_names[oparg] + ')',
IndexError: tuple index out of range
➜  py git:(master) ✗
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>虽然看不到汇编，但是我们也能从很多const量里看到很多信息：加载了rotor库，用了newcotor和encrypt函数，还有一系列变量，因此我们也可以猜测一下代码然后再试着反编译一下：</font></br>

```python
import rotor

def decrypt(data):
	key_a = '!@#$%^&*'
	key_b = 'abcdefgh'
	key_c = '<>{}:"'

	secret = key_a + key_b + key_c

	rot = rotor.newrotor(secret)
	return rot.decrypt(data)

enc = open("encrypted_flag", "rb").read()

print decrypt(enc)
```

```shell
➜  py git:(master) ✗ python dec2.py test.pyc
  ## inspecting pyc file ##
filename:     test.pyc
magic number: 0x(03 f3 0d 0a)
timestamp:    1539222518 (Thu Oct 11 09:48:38 2018)
code
   co_argcount:        0
   co_cellvars:        ()
   co_filename:        'hello.py'
   co_firstlineno:     1
   co_flags:           0x00040
   co_freevars:        ()
   co_lnotab:          '\x0c\x02\t\n\x15\x02'
   co_name:            '<module>'
   co_names:           ('rotor', 'decrypt', 'open', 'read', 'enc')
   co_nlocals:         0
   co_stacksize:       3
   co_varnames:        ()
   co_consts
      0 -1
      1 None
      2 (code object)
         co_argcount:        1
         co_cellvars:        ()
         co_filename:        'hello.py'
         co_firstlineno:     3
         co_flags:           0x00043
         co_freevars:        ()
         co_lnotab:          '\x00\x01\x06\x01\x06\x01\x06\x02\x0e\x02\x0f\x01'
         co_name:            'decrypt'
         co_names:           ('rotor', 'newrotor', 'decrypt')
         co_nlocals:         6
         co_stacksize:       2
         co_varnames:        ('data', 'key_a', 'key_b', 'key_c', 'secret', 'rot')
         co_consts
            0 None
            1 '!@#$%^&*'
            2 'abcdefgh'
            3 '<>{}:"'
         co_code
            64 01 00 7d 01 00 64 02 00 7d 02 00 64 03 00 7d
            03 00 7c 01 00 7c 02 00 17 7c 03 00 17 7d 04 00
            74 00 00 6a 01 00 7c 04 00 83 01 00 7d 05 00 7c
            05 00 6a 02 00 7c 00 00 83 01 00 53
            disassembled:
              4           0 LOAD_CONST               1 ('!@#$%^&*')
                          3 STORE_FAST               1 (key_a)

              5           6 LOAD_CONST               2 ('abcdefgh')
                          9 STORE_FAST               2 (key_b)

              6          12 LOAD_CONST               3 ('<>{}:"')
                         15 STORE_FAST               3 (key_c)

              8          18 LOAD_FAST                1 (key_a)
                         21 LOAD_FAST                2 (key_b)
                         24 BINARY_ADD
                         25 LOAD_FAST                3 (key_c)
                         28 BINARY_ADD
                         29 STORE_FAST               4 (secret)

             10          32 LOAD_GLOBAL              0 (rotor)
                         35 LOAD_ATTR                1 (newrotor)
                         38 LOAD_FAST                4 (secret)
                         41 CALL_FUNCTION            1
                         44 STORE_FAST               5 (rot)

             11          47 LOAD_FAST                5 (rot)
                         50 LOAD_ATTR                2 (decrypt)
                         53 LOAD_FAST                0 (data)
                         56 CALL_FUNCTION            1
                         59 RETURN_VALUE

      3 'encrypted_flag'
      4 'rb'
   co_code
      64 00 00 64 01 00 6c 00 00 5a 00 00 64 02 00 84
      00 00 5a 01 00 65 02 00 64 03 00 64 04 00 83 02
      00 6a 03 00 83 00 00 5a 04 00 65 01 00 65 04 00
      83 01 00 47 48 64 01 00 53
      disassembled:
        1           0 LOAD_CONST               0 (-1)
                    3 LOAD_CONST               1 (None)
                    6 IMPORT_NAME              0 (rotor)
                    9 STORE_NAME               0 (rotor)

        3          12 LOAD_CONST               2 (<code object decrypt at 0x105b50db0, file "hello.py", line 3>)
                   15 MAKE_FUNCTION            0
                   18 STORE_NAME               1 (decrypt)

       13          21 LOAD_NAME                2 (open)
                   24 LOAD_CONST               3 ('encrypted_flag')
                   27 LOAD_CONST               4 ('rb')
                   30 CALL_FUNCTION            2
                   33 LOAD_ATTR                3 (read)
                   36 CALL_FUNCTION            0
                   39 STORE_NAME               4 (enc)

       15          42 LOAD_NAME                1 (decrypt)
                   45 LOAD_NAME                4 (enc)
                   48 CALL_FUNCTION            1
                   51 PRINT_ITEM
                   52 PRINT_NEWLINE
                   53 LOAD_CONST               1 (None)
                   56 RETURN_VALUE

  ## done inspecting pyc file ##
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>用这个做参考，我们可以试着去猜测一下crypt.pyc的机器码，根据混淆后的opcode，我们看到最后一个字节是return value，对于一个函数调用来说，似乎这个字节没错，猜测**最后一个字节并没有被混淆**。随后开头可以看到一系列类似LOAD，STORE的机器码串，操作数都是0100，0200，猜测**操作数也没有被混淆**，且猜测**0x99对应0x64，0x68对应0x7D**，看来混淆算法并不是单纯的加减或者异或操作，更像是映射，所以没法直接求源代码了。继续分析后我们可以猜测出如下汇编：</font></br>

```
990100	LOAD_CONST	1 ('!@#$%^&*')
680100	STORE_NAME	1 (key_a)
990200	LOAD_CONST	2 ('abcdefgh')
680200	STORE_NAME	2 (key_b)
990300	LOAD_CONST	3 ('<>{}:"')
680300	STORE_NAME	3 (key_c)
610100	LOAD_FAST	1 (key_a)
990400	LOAD_CONST	4 (4)
46
990500	LOAD_CONST	5 ('|')
27
610200	LOAD_FAST	2 (key_b)
610100	LOAD_FAST	1 (key_a)
27
610300	LOAD_FAST	3 (key_c)
27
990600	LOAD_CONST	6 (2)
46
27
990500	LOAD_CONST	5 ('|')
27
610200	LOAD_FAST	2 (key_b)
990600	LOAD_CONST	6 (2)
46
27
990700	LOAD_CONST	7 ('EOF')
27
680400	STORE_NAME	4 (secret)
9b0000	LOAD_GLOBAL	0 (rotor)
600100	LOAD_ATTR	1 (newrotor)
610400	LOAD_FAST	4 (secret)
830100	CALL_FUNCTION 1
680500	STORE_NAME	5 (rot)
610500	LOAD_FAST	0 (rot) 
600200	LOAD_ATTR	2 (decrypt)
610000	LOAD_FAST	0 (data)
830100	CALL_FUNCTION 1
53	RETURN_VALUE
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>只剩下0x46,0x27不得知了，最终的字符串操作类似如下：</font></br>

```
secret = (key_a OP46 4) OP27 '|' OP27 ((key_b OP27 key_a OP27 key_c) OP46 2) OP27 '|' OP27 (key_b OP46 2) OP27 'EOF'
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>0x27这个机器码非常多，且0x46这个机器码通常连接字符串和数字附近，能合法这样操作的最常用的就是*（乘号了），OP27经常连接字符串与字符串，最常用的就是+号，因此我们可以猜测出如下脚本：</font></br>

```python
import rotor

def decrypt(data):
	key_a = '!@#$%^&*'
	key_b = 'abcdefgh'
	key_c = '<>{}:"'
	
	secret = key_a*4 + '|' + (key_b+key_a+key_c)*2 + '|' + key_b*2 + 'EOF'
	
	rot = rotor.newrotor(secret)
	return rot.decrypt(data)

i = open("encrypted_flag", "rb").read()

print decrypt(i)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>运行后成功得到flag{Gue55_opcode_G@@@me}</font></br>