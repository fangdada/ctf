import binascii

key='4b404c4b5648725b445845734c735949405c414d5949725c45495a51'
guess='qctfQCTFflag'

key=binascii.a2b_hex(key)

for n in range(0,3):
  for i,j in zip(key[:4],guess[n*4:(n+1)*4]):
    print ord(i)^ord(j),
  print ''

flag=''
n=1
for i in key:
  if(n&1):
    flag+=chr(ord(i)^45)
  else:
    flag+=chr(ord(i)^44)
  n+=1

print flag
