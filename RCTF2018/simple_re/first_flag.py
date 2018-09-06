from z3 import *
key=[ 
  0x556E4969,
  0x2E775361,
  0x893DAE7,
  0x96990423,
  0x6CF9D3E9,
  0xA505531F,
  0x54A0B9BD,
  0x4B818640,
  0x8EB63387,
  0xA9EABEFD,
  0xB8CDF96B,
  0x113C3052]

flag=[]

for i in xrange(6):
  flag.append(BitVec(i,32))

s=Solver()

for i in xrange(6):
  s.add(key[i]*flag[i]==key[i+6])

if s.check()==sat:
  print s.model()

# we got 
# 5o_M@ny_an7i_Rev3rsing_T
