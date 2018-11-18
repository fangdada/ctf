#!/bin/python

import binascii
from sub17A0 import *
from sub1660 import *

size_hash=0xD31580A28DD8E6C4
flag_hash=0xAA302D9E67AAC4BA

gen_flag=lambda x:binascii.a2b_hex(hex(x)[2:][:-1])[::-1]
gen_flag2=lambda x:binascii.a2b_hex(hex(x)[2:])[::-1]

for i in range(0,255):

    table=encry17A0([i,0,0,0],0)
    myhash=encry1660(table)

    if myhash==size_hash:
        print 'get the size:'+str(i)
        

for f0 in range(0x30,0x3a):
    print f0
    for f1 in range(0x30,0x3a):
        for f2 in range(0x30,0x3a):
            for f3 in range(0x30,0x3a):
                for f4 in range(0x30,0x3a):
                    for f5 in range(0x30,0x3a):
                        for f6 in range(0x30,0x3a):
                            for f7 in range(0x30,0x3a):
                                for f8 in range(0x30,0x3a):
                                    for f9 in range(0x30,0x3a):
                                        num1=((((((((f7<<8)|f6)<<8|f5)<<8|f4)<<8|f3)<<8|f2)<<8|f1)<<8|f0)
                                        num2=(((f9<<8)|f9)<<8|f8)
                                        table=encry17A0([num1,0,num2,0],1)
                                        myhash=encry1660(table)
                                        print hex(myhash)
                                        exit()
                                        if myhash==flag_hash:
                                            print 'get the flag'
                                            print 'hxb2018{'+gen_flag(num1)+gen_flag2(num2&0x00ffff)+'}'


# input:    01234567 89
# convert to  ====>
# input:    76543210 998

#num1=int(binascii.b2a_hex('76543210'),16)
#num2=int(binascii.b2a_hex('998'),16)

#table=encry17A0([num1,0,num2,0],1)
#myhash=encry1660(table)

#print hex(myhash)
 

