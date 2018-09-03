#encoding:utf-8

key="\xDA\xD8\x3D\x4C\xE3\x63\x97\x3D\
\xC1\x91\x97\x0E\xE3\x5C\x8D\x7E\
\x5B\x91\x6F\xFE\xDB\xD0\x17\xFE\
\xD3\x21\x99\x4B\x73\xD0\xAB\xFE"


def encrypt(input):
  output1=''
  output2=''
  output3=''
  for i in range(0,len(input),4):
    output1+=input[i+2]+input[i]+input[i+3]+input[i+1]
  
  for i in range(0,len(output1),4):
    output2+=chr(ord(output1[i])+0x7)
    output2+=chr(ord(output1[i+1])+0x12)
    output2+=chr(ord(output1[i+2])+0x58)
    output2+=chr(ord(output1[i+3])+0x81)

  for i in range(0,len(output2),4):
    output3+=chr((ord(output2[i])>>5)|((ord(output2[i])<<3)&0xff))
    output3+=chr((ord(output2[i+1])>>2)|((ord(output2[i+1])<<6)&0xff))
    output3+=chr((ord(output2[i+2])>>7)|((ord(output2[i+2])<<1)&0xff))
    output3+=chr((ord(output2[i+3])>>4)|((ord(output2[i+3])<<4)&0xff))
  

  return output3



def decrypt(input):
  output1=''
  output2=''
  output3=''

  for i in range(0,len(input),4):
    output1+=chr(((ord(input[i])<<5)&0xff)|(ord(input[i])>>3))
    output1+=chr(((ord(input[i+1])<<2)&0xff)|(ord(input[i+1])>>6))
    output1+=chr(((ord(input[i+2])<<7)&0xff)|(ord(input[i+2])>>1))
    output1+=chr(((ord(input[i+3])<<4)&0xff)|(ord(input[i+3])>>4))

  for i in range(0,len(output1),4):
    output2+=chr(ord(output1[i])-0x7)
    output2+=chr(ord(output1[i+1])-0x12)
    output2+=chr(ord(output1[i+2])-0x58)
    output2+=chr(ord(output1[i+3])-0x81)
    
  for i in range(0,len(output2),4):
    output3+=output2[i+1]+output2[i+3]+output2[i]+output2[i+2]

  return output3



if __name__ == '__main__':
  
  input='0123456789abcdefghijklmnopqrstuv'
  output=encrypt(input)

  flag=decrypt(key)
  print flag

  #QCTF{Rus4_1s_fun4nd_1nt3r3st1ng}
