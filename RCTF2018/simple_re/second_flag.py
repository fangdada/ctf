#encoding:utf-8

import math

Euler=4132027200
mod=0xF64BB17D
win=0x6F82C8DC

#dirt='0123456789abcdefghijklmnopqrstuvwxzy!*_'
dirt="echnique!13"

def Is_Prime(prime):
  if prime%2==0:
    return False
  sqrtnum=int(math.sqrt(prime))
  for i in range(3,sqrtnum+1,2):
    if prime%i==0:
      return False
  return True

def get_prime_arr():
  prime_arr=[]
  for i in range(3,0xffff):
    if(Is_Prime(i)):
      if(prime_with(i,Euler)):
        prime_arr.append(i)
  return prime_arr

def prime_with(num,Euler):
  if Euler%num==0:
    return False
  else:
    return True

def check(words,key):
  return words**key%mod

def check2(words,i,flag,real_prime):
  temp=0
  for k in words:
    temp^=k
  temp^=flag[i]
  temp^=real_prime[i]
  one=(temp)>>8
  two=temp&0xff
  return (one^two)


def get_word3(word1,word2):
  i=word2
  ptr=word1
  while(i&ptr):
    temp=ptr
    ptr^=i
    i=2*(i&temp)
  return (i|ptr)


print "Start collect key dirt..."

prime=get_prime_arr()
flag3=[]
real_prime=[]

print "prime dirt collected successfully. Len:%d"%(len(prime))

#j=0
for i in prime:
  for a in dirt:
    for b in dirt:
      temp=(ord(a)<<8)+(ord(b))
      if(get_word3(i,temp)==0xA496):
        flag3.append(temp)
        real_prime.append(i)

print "flag3 dirt collected done. Len:%d"%(len(flag3))
print "The len of real_prime:%d"%(len(real_prime))

j=len(flag3)
flag1=[0,0,0,0,0]
real_flag1=[[]]

for i in range(0,j):
  real_flag1.append([])
  for a in dirt:
    for b in dirt:
      for c in dirt:
        for d in dirt:
          flag1[0]=(ord(a)<<8)+ord(b)
          flag1[1]=(ord(c)<<8)+ord(d)
          if(check2(flag1,i,flag3,real_prime)==22):
            real_flag1[i].append((flag1[0]<<16)+flag1[1])

print "flag1 collected successfully, start to brute..."


k=0
for i in real_flag1:
  print "Brute step:%d len:%d"%(k,len(i))
  for j in i:
    if(check(j,real_prime[k])==win):
      print "Got the flag: %x%x%x"%(j,real_prime[k],flag3[k])
      exit()
  k+=1
#we got 'echnu3!q'
#so the flag is:5o_M@ny_an7i_Rev3rsing_Technu3!q
print "Bruted finished."

