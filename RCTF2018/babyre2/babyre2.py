from z3 import *

xmmword_602060=0x7BA58F82BD8980352B7192452905E8FB
xmmword_602070=0x163F756FCC221AB0A3112746582E1434
xmmword_602080=0x0DCDD8B49EA5D7E14ECC78E6FB9CBA1FE
xmmword_602090=0x0AAAAAAAAAA975D1CA2845FE0B3096F8E
xmmword_6020A0=0x55555555555559A355555555555559A3
xmmword_6020B0=0x55555555555559A355555555555559A3
xmmword_6020C0=0x55555555555559A355555555555559A3
xmmword_6020D0=0x55555555555559A355555555555559A3

def _mm_load_si128(a):
  return a

def _mm_or_si128(a,b):
  return a|b

def _mm_xor_si128(a,b):
  return a^b

def _mm_srli_si128(a,b):
  return a>>b

def ascii(x):
  s=''
  for i in xrange(8):
    s=s+chr(x&0xff)
    x=x>>8
  return s

def multi_mod(b,e,m):
  result=1
  while e!=0:
    if(e&1)==1:
      result=(result*b)%m
    e>>=1
    b=(b*b)%m
  return result

#a*b%c=d
#a=d*b^(c-2)%c
def re_mod(d,b):
  c=0xffffffffffffffC5
  s=d*multi_mod(b,(c-2),c)%c
  return s

def unp(x,i):
  if i==0:
    return res[x].as_long()&0xffffffffffffffff
  else:
    return res[x].as_long()>>64

v40=BitVec('v40',128)
v41=BitVec('v41',128)
v42=BitVec('v42',128)
v43=BitVec('v43',128)
v44=BitVec('v44',128)
v45=BitVec('v45',128)
v46=BitVec('v46',128)
v47=BitVec('v47',128)

s=Solver()

v6 = _mm_or_si128(
         _mm_xor_si128(_mm_load_si128(xmmword_6020D0), v47),
         _mm_or_si128(
           _mm_xor_si128(_mm_load_si128(v46), xmmword_6020C0),
           _mm_or_si128(
             _mm_xor_si128(_mm_load_si128(v45), xmmword_6020B0),
             _mm_or_si128(
               _mm_xor_si128(_mm_load_si128(v44), xmmword_6020A0),
               _mm_or_si128(
                 _mm_xor_si128(_mm_load_si128(v43), xmmword_602090),
                 _mm_or_si128(
                   _mm_xor_si128(_mm_load_si128(v42), xmmword_602080),
                   _mm_or_si128(
                     _mm_xor_si128(v40, xmmword_602060),
                     _mm_xor_si128(_mm_load_si128(xmmword_602070), v41))))))))

s.add(v6==0)
if s.check()==sat:
  print s.model()

res=s.model()

flag = ascii(re_mod(unp(v40,0),0x20656D6F636C6557))
flag += ascii(re_mod(unp(v40,1),0x2046544352206F74))
 
flag += ascii(re_mod(unp(v41,0),0x6548202138313032))
flag += ascii(re_mod(unp(v41,1),0x2061207369206572))
 
flag += ascii(re_mod(unp(v42,0),0x6320455279626142))
flag += ascii(re_mod(unp(v42,1),0x65676E656C6C6168))
 
flag += ascii(re_mod(unp(v43,0), 0x756F7920726F6620))
flag += ascii(re_mod(unp(v43,1), 0xFFFFFFFFFFFF002E))
 
flag += ascii(re_mod(unp(v44,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(re_mod(unp(v44,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(re_mod(unp(v45,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(re_mod(unp(v45,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(re_mod(unp(v46,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(re_mod(unp(v46,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(re_mod(unp(v47,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(re_mod(unp(v47,1), 0xFFFFFFFFFFFFFFFF))
print flag

