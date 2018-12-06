#encoding:utf-8
import binascii

#inputs='0123456789abcde'
result=[]

'''
flag='2E 00 26 00 2D 00 29 00  4D 00 67 00 05 00 44 00\
      1A 00 0E 00 7F 00 7F 00  7D 00 65 00 77 00 24 00\
      1A 00 5D 00 33 00 51 00  00 00 00 00 00 00 00 00'
'''

flag='2E262D294D6705441A0E7F7F7D6577241A5D3351'

Flag=''

recorver=[]
for i in binascii.a2b_hex(flag):
    recorver.append(ord(i))

n=0x48
for i in range(len(recorver)):
    recorver[i]^=n
    n+=2

# encrypt:
'''
for i in range(4):
    for j in range(1,len(recorver)):
        recorver[j]^=recorver[j-1]
'''
# decrypt:
for i in range(4):
    for j in range(len(recorver)-1,0,-1):
        recorver[j]^=recorver[j-1]

print ''.join(map(chr,recorver))

