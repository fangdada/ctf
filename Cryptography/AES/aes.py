import binascii
import sys
from aes_tools import AES_tools

# S-box
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

# reversed S-box
rsbox= [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
        0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
        0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
        0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
        0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
        0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
        0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
        0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
        0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
        0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
        0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
        0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
        0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
        0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
        0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
        0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
        0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
        0x21, 0x0c, 0x7d]


# round XOR array
Rcon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]




MixMatrix=[[2,3,1,1,],[1,2,3,1],[1,1,2,3],[3,1,1,2]]

InvMixMatrix=[[0xe,0xb,0xd,9],[9,0xe,0xb,0xd],[0xd,9,0xe,0xb],[0xb,0xd,9,0xe]]





# look up for Nr by AES-mode
r={'128':10,'192':12,'256':14,'test':4}


# get one byte for a 32-bits num
get_byte = lambda a,i: (a>>(24-(i*8)))&0xff

# matrix rotation for State
rotate = lambda x:map(list,zip(*x))



# used for two arrays
def xor(w1,w2):

    w=[]
    for i,j in zip(w1,w2):
        w.append(i^j)

    return w



# used for Rcon xor
def XOR(w,r):

    temp=[]
    for i,c in zip(w,range(0,len(w))):
            temp.append(i^get_byte(r,c))

    return temp


def matrix_multi(m1,m2):

    result=[]

    if len(rotate(m1))!=len(m2):
        print 'the size of matrix doesn\'t match multiplication standard'
        return None

    for i in range(0,len(m2)):
        result.append([])
        for j in range(0,len(rotate(m2))):
            temp=0
            for n1,n2 in zip(m1[i],rotate(m2)[j]):
                temp^=GF_multi(n2,n1)
            result[i].append(temp)

    return result
        

    
    




#=================================================
# text_set will be filled like:
# 
#                   State[]
#               __________________________
#   group_count |_________________________
#               |_________________________
#               |_________________________
#               |_________________________
#
#
#
# State is a 4*Nb bytes matrix
#   _____________
#   |__|__|__|__|
#   |__|__|__|__|
#   |__|__|__|__|
#   |__|__|__|__|
#



def padding_plaintext(string,group_count):

    text_set=[]
    Nb=4

    for i in range(0,group_count):
        text_set.append([])
        for j in range(0,Nb):
            text_set[i].append(list(ord(k) for k in string[i*16+j*4:i*16+(j+1)*4:]))
        text_set[i]=rotate(text_set[i])

    return text_set






#==================================================
# key_set will be filled like:
#
#           Nk-bytes w[Nk]
#       _______________________
#   Nk  |______________________
#       |______________________
#       |______________________
#       |______________________
#       |______________________
#       
#


def padding_key(key,mode):

    key_set=[]
    key=key+' '*(mode/8-len(key))
    Nk=mode/32

    for i in range(0,Nk):
        key_set.append(list(ord(k) for k in key[i*4:(i+1)*4]))

    return key_set





# something like above
# key will be expanded to [Nk,Nb*(Nr+1)]
#
#
#   w[0-Nk] is a 32-bits block
#   
#   ___________________
#   |k0 |k4 |k8 |k12...
#   |   |   |   |
#   |k1 |k5 |k9 |k13...
#   |   |   |   |
#   |k2 |k6 |k10|k14...
#   |   |   |   |
#   |k3 |k7 |k11|k15...
#
#    ^  ^   ^   ^
#    |  |   |   |
#    |  |   |   |
#    w0 w1  w2  w3...w[Nk-1]
#

def key_Expand(key,mode):

    Nk=mode/32
    Nb=4
    Nr=r[str(mode)]
    K=Nb*(Nr+1)

    final_key=[]
    generate_key=[]
    w=[]

    for i in range(0,Nk):
        w.append(key[i])

    
    for i in range(Nk,K):
        if i%Nk==0:
            w.append(xor(w[i-Nk],g(w[i-1],i,Nk)))
        else:
            w.append(xor(w[i-Nk],w[i-1]))

    return w

        

# call g function while i%Nk==0
# g function will do something like:
#
#
#           w
#           ^
#           |
#           |
#           |
#   _________________
#   |B0 |B1 |B2 |B3 |
#   |___|___|___|___|
#           |
#           |
#   left_move_one_bytes
#           |
#   ________|________
#   |B1 |B2 |B3 |B4 |  
#   |___|___|___|___|
#     |   |   |   |
#     |   |   |   |
#     S   S   S   S     S-boxes subbytes
#     |   |   |   |
#   __|___|___|___|__   ____________________________________
#   |B1'|B2'|B3'|B4'| ^ |Rcon[j/4-1]|0      |0      |0      |       >>>>>   w'  (output)
#   |___|___|___|___|   |___________|_______|_______|_______|       >>>>>
#


def g(w,count,Nk):
    
    temp=w[1:]+[w[0]]
    for i,c in zip(temp,range(0,len(temp))):
        temp[c]=sbox[((i>>4)*0x10)+(i&0xf)]

    return XOR(temp,Rcon[count/Nk-1])


def SubBytes(plain_text,rev):

    temp=[]
    for i in plain_text:
        temp.append(i)

    if rev==0:
        box=sbox
    else:
        box=rsbox


    for i in range(0,len(temp)):
        for j in range(len(temp[i])):
            temp[i][j]=box[((temp[i][j]>>4)*0x10)+(temp[i][j]&0xf)]
            
    return temp
    

def ShiftRows(plain_text,rev):

    temp=[]
    for i in plain_text:
        temp.append(i)

    if rev==0:
        for i in range(0,4):
            temp[i]=temp[i][i:]+temp[i][0:i]
    else:
        for i in range(0,4):
            temp[i]=temp[i][4-i:4]+temp[i][:4-i]


    return temp



def MixColumns(plain_text,rev):

    if rev==0:
        return matrix_multi(MixMatrix,plain_text)
    else:
        return matrix_multi(InvMixMatrix,plain_text)




def AddRoundKey(plain_text,key,key_round):

    temp=[]

    for i in range(0,len(rotate(plain_text))):
        temp.append(xor(rotate(plain_text)[i],key[key_round*4+i]))

    temp=rotate(temp)

    return temp


def last_round_decrypt(plain_text,key):

    temp=[]

    for i in plain_text:
        temp.append(i)

    temp=AddRoundKey(temp,key,0)
    temp=ShiftRows(temp,1)
    temp=SubBytes(temp,1)

    return temp

    


#===========================================
# GF(2^8) multiplication
# waiting....
#

def GF_multi(source_num,multi_num):
 
    a=source_num
    b=multi_num
        
    p = 0
    for counter in range(8):
        if b & 1: p ^= a
        if a&0x80:
            a=(((a<<1)&0xff)^0x1b)
        else:
            a=(a<<1)&0xff

        b >>= 1
    return p


def copy_cipher_text(plaintext):

    temp=[]
    for i in plaintext:
        temp.append(i)
    return temp



class AES(object):

    plaintext=[]
    key=[]
    Nb=4
    Nk=4
    Nr=10
    mode=128

    ciphertext=[]

    def __doc__(self):

        print '\n'
        print 'Author: fanda    mail:1278466220@qq.com'
        print 'This AES program support AES-128, AES-192, AES-256 \n'
        print 'use initAES(<plain text>,<key>,<mode>) to initialize a AES-standard cipher text and key.'
        print 'use show(flag1,flag2)    flag1 set 1 to show cipher text and key, flag2 set 1 to show nothing now :)'
        print ''









    def initAES(self,string,key,mode=128):

        self.plaintext=[]
        self.key=[]

        if(mode!=128 and mode!=192 and mode!=256):
            print 'AES encrypt mode not specific, using AES-128'
        else:
            self.mode=mode
            self.Nk=self.mode/32
            self.Nr=r[str(self.mode)]

        if len(string)==0 or len(key)==0:
            return 'please complete the input'

        align=self.Nb*4
        group_count=len(string)/align if len(string)%align==0 else len(string)/align+1
        string+=' '*(group_count*align-len(string))



        #===================================================
        # plain text and key padding to standard length
        # then use key expansion:

        self.plaintext=padding_plaintext(string,group_count)
        self.key=padding_key(key,self.mode)
        self.key=key_Expand(self.key,self.mode)


        #====================================================
        # after key expansion,
        # start to encrypt plain text, which is used by State

        print 'x3 pair:'
        for g in range(0,group_count):
            self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,0)
            for i in range(1,self.Nr):
                self.plaintext[g]=SubBytes(self.plaintext[g],0)
                self.plaintext[g]=ShiftRows(self.plaintext[g],0)
                self.plaintext[g]=MixColumns(self.plaintext[g],0)
                self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,i)
            print self.plaintext[g][0][0]
            self.plaintext[g]=SubBytes(self.plaintext[g],0)
            self.plaintext[g]=ShiftRows(self.plaintext[g],0)
            self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,self.Nr)


        self.ciphertext=copy_cipher_text(self.plaintext)

        # plain text -> cipher text
        # here is a 0-round, which is just an AddRoundKey method
        # and the last-round that doesn't contain MixColumns
        #====================================================
        # here to decrypt:

        for g in range(0,group_count):
            self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,self.Nr)
            self.plaintext[g]=ShiftRows(self.plaintext[g],1)
            self.plaintext[g]=SubBytes(self.plaintext[g],1)
            for i in range(self.Nr-1,0,-1):
                self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,i)
                self.plaintext[g]=MixColumns(self.plaintext[g],1)
                self.plaintext[g]=ShiftRows(self.plaintext[g],1)
                self.plaintext[g]=SubBytes(self.plaintext[g],1)
            self.plaintext[g]=AddRoundKey(self.plaintext[g],self.key,0)





    def auto_diff_analy(self,string,key,mode):

        self.Nr=4
        self.initAES(string,key,'test')
        ciphertext=[]
        ciphertext_bak=[]
        count=0


        for i in self.ciphertext:
            ciphertext.append(i)
            ciphertext_bak.append(i)


        possible_key=set([i for i in range(0,256)])
        blank=[[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

        '''
        for k in range(0,256):

            #possible_key=set([i for i in range(0,256)])
            key=[[k,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
            test1=[[],[],[],[]]
            test2=[[],[],[],[]]

            for i in range(0,len(ciphertext)):
                ciphertext[i]=last_round_decrypt(ciphertext_bak[i],key)


            #for i in range(0,4):
            #    test1[i]=xor(ciphertext[0][i],ciphertext[1][i])
            #    test2[i]=xor(last_round_decrypt(ciphertext_bak[0],blank)[i],last_round_decrypt(ciphertext_bak[1],blank)[i])


            #for i in range(1,len(ciphertext_bak)):
            #    if ciphertext_bak[0][0][0]==ciphertext_bak[i][0][0]:
            #        print 'got it:'+str(k)+' and the i:'+str(i)


            for i in range(1,len(ciphertext)):
                if ciphertext[0][0][0]==ciphertext[i][0][0]:
                    print ciphertext[i]
                    print 'got it:'+str(k)+' and the i:'+str(i)
                    possible_key-=set([ciphertext[i][0][0]])
                    #break

        print 'target key:'+str(self.key[4*4+3][0])
        print possible_key
        '''


        #for i in range(1,256):

            #key=[[i,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

            #print self.ciphertext[255]
            #recorver=last_round_decrypt(self.ciphertext[255],key)[0][0]
            #print recorver
            #return ''

            #if self.ciphertext[255][0][0]==sbox[(recorver>>4)*0x10+(recorver&0xf)]:
            #    print 'got it, key is'+str(i)
            #    break

            #print self.ciphertext[0][0][0]^self.ciphertext[1][0][0]
            #print last_round_decrypt(self.ciphertext[0],key)[0][0]^last_round_decrypt(self.ciphertext[1],key)[0][0]

        #print self.ciphertext[0][0][0]^self.ciphertext[1][0][0]
        #print last_round_decrypt(self.ciphertext[0],key)[0][0]^last_round_decrypt(self.ciphertext[1],key)[0][0]

        #return ''


        key=[[0x3,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

        print 'x4 cipher pair:'
        print self.ciphertext[0][0][0]
        print self.ciphertext[1][0][0]
        print

        #x3=54
        #X3=201
        #print sbox[((x3>>4)*0x10)+(x3&0xf)]^sbox[((X3>>4)*0x10)+(X3&0xf)]

        x3=last_round_decrypt(self.ciphertext[0],key)[0][0]
        X3=last_round_decrypt(self.ciphertext[1],key)[0][0]
        x4=self.ciphertext[0][0][0]
        X4=self.ciphertext[1][0][0]
        print 'guess x3 cipher pair:'
        print str(x3)+' '+str(X3)
        print 'guess key x3 xor:'
        print x3^X3
        print 'sbox xor:'
        print sbox[((x3>>4)*0x10)+(x3&0xf)]^sbox[((X3>>4)*0x10)+(X3&0xf)]
        print 'right xor:'
        print self.ciphertext[0][0][0]^self.ciphertext[1][0][0]

        print 'our key:'+hex(key[0][0])[2:]
        print 'target key:'+hex(self.key[self.Nr*4][0])[2:]
        return ''



        for i in range(1,len(ciphertext_bak)):

            print i
            for k in range(0,256):

                key=[[k,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
                ciphertext[0]=last_round_decrypt(ciphertext_bak[0],key)
                ciphertext[i]=last_round_decrypt(ciphertext_bak[i],key)

                #print ciphertext_bak[0][0][0]^ciphertext_bak[i][0][0],
                #print ciphertext[0][0][0]^ciphertext[i][0][0]

                if ciphertext[0][0][0]^ciphertext[i][0][0]==ciphertext_bak[i][0][0]^ciphertext_bak[0][0][0]:
                    print 'got it:'+str(k)
                    possible_key-=set([k])

        print possible_key

        print 'target key:'+str(self.key[4*4+3][0])



        



    def show_xor(self):

        print 'plain text pairs:'
        for i in range(0,len(self.plaintext)/2):
            print 'pair '+str(i)+':'
            for a,b in zip(self.plaintext[i],self.plaintext[i+1]):
                print xor(a,b)
        print '\n'

        print 'cipher text pairs:'
        for i in range(0,len(self.ciphertext)/2):
            print 'pair '+str(i)+':'
            for a,b in zip(self.ciphertext[i],self.ciphertext[i+1]):
                print xor(a,b)
        print '\n'





    def show(self,show_key=0):

        '''
        print 'plain text:'
        for i in range(0,len(self.plaintext)):
            print 'Group '+str(i)+':'
            for j in self.plaintext[i]:
                print j
        print '\n'
        '''

        if show_key==1:
            print '\nkey after expanded:'
            print 'length:'+str(len(self.key))
            for i in self.key:
                for j in i:
                    print hex(j)[2:],
                print 
            print '\n'

        '''
        print 'cipher text:'
        for i in range(0,len(self.ciphertext)):
            print 'Group '+str(i)+':'
            for j in rotate(self.ciphertext[i]):
                for k in j:
                    print hex(k)[2:],
                print 
        print '\n'
        '''


if __name__ == '__main__':
    
    a=AES()

    #strings=AES_tools().change_first_byte('wohehehehe',255)
    strings=AES_tools().change_first_byte('wellwellwell',1)

    #a.initAES(strings,'bbbbbbbb',128)
    #a.auto_diff_analy(strings,'01234567',128)
    a.auto_diff_analy(strings,'0123456789abcdef',128)

    #a.show(1)
    #a.show_xor()





