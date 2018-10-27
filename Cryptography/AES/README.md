# AES差分分析
## Author: fanda
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>AES比DES难一些，开始需要一些理论上的知识，并且加密过程也没有DES那样简单的替换异或，因此还是比较复杂的，但效率和安全性都比DES高。因此相对DES，AES以及其他Hash之类的差分攻击研究也更有需要一些。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>老样子，要自己实现差分的话首先要有这么一个加密模型，重复造个轮子，用python写个简单的AES，类似DES，还是持续性更新，从完成基本的加密开始吧:)</font></br>

- beta1
> 实现了密钥扩展模块
- beta2
> 实现了基本的加解密功能
- beta3
> 遇到4轮AES不可能差分理论上的问题，搁置...


目前进度
=================

```shell

fanda@fanda:~/Desktop/ctf/Cryptography/AES$ python aes.py

AES encrypt mode not specific, using AES-128
x3 pair:
54
201
x4 cipher pair:
60
228

guess x3 cipher pair:
37 176
guess key x3 xor:
149
sbox xor:
216
right xor:
216
our key:3
target key:39


```