import binascii
import sys

# Author:fanda
# mail is followed


# define the DES boxes

S=  [[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],      #S1
    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], 
    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], 
    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],       #S2
    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], 
    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], 
    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],       #S3
    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], 
    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], 
    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],       #S4
    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], 
    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], 
    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]] ,

    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],       #S5
    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], 
    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], 
    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]] ,

    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],       #S6
    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], 
    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], 
    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]] ,

    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],       #S7
    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], 
    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], 
    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]] ,

    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],       #S8
    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], 
    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], 
    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]

PC1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,
     10,2,59,51,43,35,27,19,11,3,60,52,44,36,
     63,55,47,39,31,23,15,7,62,54,46,38,30,22,
     14,6,61,53,45,37,29,21,13,5,28,20,12,4]

PC2=[14,17,11,24,1,5,3,28,15,6,21,10,
     23,19,12,4,26,8,16,7,27,20,13,2,
     41,52,31,37,47,55,30,40,51,45,33,48,
     44,49,39,56,34,53,46,42,50,36,29,32]

LOOP=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

IP1=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
     38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
     36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
     34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

E=[32,1,2,3,4,5,4,5,6,7,8,9,
   8,9,10,11,12,13,12,13,14,15,16,17,
   16,17,18,19,20,21,20,21,22,23,24,25,
   24,25,26,27,28,29,28,29,30,31,32,1]

P=[16,7,20,21,
   29,12,28,17,
   1,15,23,26,
   5,18,31,10,
   2,8,24,14,
   32,27,3,9,
   19,13,30,6,
   22,11,4,25]

#===============================================================
# customize part:

# get a num's first and last bit 
# or get the middle 4 bits
h=lambda x:((x>>5)<<1)+(x&1)
l=lambda x:(x>>1)&0xf

ENCRYPT=0
DECRYPT=1


# customize 'xor' function
# for support my bit array only
#   '0'=='0'    --->    '0'
#   '0'!='1'    --->    '1'
#   '1'=='1'    --->    '0'

def xor(side1,side2):
    temp=[]
    if(len(side1)!=len(side2)):
        return 'xor length not satisfied!'
    else:
        for i,j in zip(side1,side2):
            if i==j:
                temp.append('0')
            else:
                temp.append('1')
    return temp




# customize a char or a hexadecimal number to binary function
# he can convert any char to bin string 
# like convert 'a' to '01100001' or f to '1111'

def c2bin(ch):
    b=bin(ord(ch))[2:]
    b='0'*(8-len(b))+b
    return b
 
def n2bin(n):
    b=bin(n)[2:]
    b='0'*(4-len(b))+b
    return b




#============================================================
# DES encrypt part:


# function can be reused
# support IP,IP1,P,E-box exchange

def exchange(table,string):
    temp=[]
    for i in table:
        temp.append(string[i-1])
    return temp


# S-box exchange
# convert 6 bits num to 4 bit
# for exm: 
# input 010111 (sellect S1[1][11])  --->    1011

def S_exchange(string):
    temp=[]
    result=[]
    for i in range(0,8):
        temp.append(string[i*6:(i+1)*6])
    for i,s in zip(temp,S):
        n=n2bin(s[int(i[0]+i[5],2)][int(''.join(i[1:5]),2)])
        for j in n:
            result.append(j)
    return result





# *******************************************************************************************************
# loop 16 times to generate key
# for example:
# input key: '01234567'
# then we get:
# 
# K1:	0 1 0 1 0 0 0 0 0 0 1 0 1 1 0 0 1 0 1 0 1 1 0 0 0 1 0 1 0 1 0 0 0 0 1 0 0 0 1 1 0 1 0 0 0 1 1 1
# K2:	0 1 0 1 0 0 0 0 1 0 1 0 1 1 0 0 1 0 1 0 0 1 0 0 0 1 1 1 0 1 0 0 1 0 0 0 0 0 0 1 0 1 0 0 0 1 0 1
# K3:	1 1 0 1 0 0 0 0 1 0 1 0 1 1 0 0 0 0 1 0 0 1 1 0 0 1 0 0 0 0 1 0 1 0 1 0 0 1 0 0 1 1 0 0 1 1 1 0
# K4:	1 1 1 0 0 0 0 0 1 0 1 0 0 1 1 0 0 0 1 0 0 1 1 0 0 1 1 0 1 1 0 0 1 0 1 1 0 1 0 1 1 0 0 0 1 0 0 1
# K5:	1 1 1 0 0 0 0 0 1 0 0 1 0 1 1 0 0 0 1 0 0 1 1 0 0 0 1 0 1 0 1 0 0 1 0 1 0 1 0 0 0 1 1 0 1 0 1 1
# K6:	1 1 1 0 0 0 0 0 1 0 0 1 0 0 1 0 0 1 1 1 0 0 1 0 0 1 0 0 1 1 1 0 1 1 0 1 1 0 0 1 0 0 1 0 0 0 1 0
# K7:	1 0 1 0 0 1 0 0 1 1 0 1 0 0 1 0 0 1 1 1 0 0 1 0 1 0 0 0 0 1 0 0 0 1 0 0 1 1 0 1 0 1 1 1 1 0 0 0
# K8:	1 0 1 0 0 1 1 0 0 1 0 1 0 0 1 1 0 1 0 1 0 0 1 0 1 1 0 0 1 0 0 1 1 0 0 1 1 0 1 0 0 1 0 1 0 0 0 0
# K9:	0 0 1 0 0 1 1 0 0 1 0 1 0 0 1 1 0 1 0 1 0 0 1 1 1 1 0 0 1 0 0 1 1 0 0 0 0 0 1 0 0 1 1 1 1 0 0 0
# K10:	0 0 1 0 1 1 1 1 0 1 0 1 0 0 0 1 0 1 0 1 0 0 0 1 1 0 0 1 0 0 0 1 1 1 0 1 1 1 1 0 0 0 0 0 1 1 0 0
# K11:	0 0 0 0 1 1 1 1 0 1 0 0 0 0 0 1 1 1 0 1 1 0 0 1 0 0 0 1 1 0 0 0 0 0 0 1 0 1 1 0 1 0 1 1 0 1 0 0
# K12:	0 0 0 1 1 1 1 1 0 1 0 0 0 0 0 1 1 0 0 1 1 0 0 1 1 0 0 1 1 0 0 1 0 1 1 0 1 0 0 0 1 0 1 0 0 1 0 1
# K13:	0 0 0 1 1 1 1 1 0 0 0 0 1 0 0 1 1 0 0 0 1 0 0 1 0 0 1 0 0 0 1 0 0 1 1 0 1 0 1 0 1 0 0 1 0 0 0 1
# K14:	0 0 0 1 1 0 1 1 0 0 1 0 1 0 0 0 1 0 0 0 1 1 0 1 1 0 1 1 0 0 1 1 0 0 1 0 0 0 0 1 0 0 0 1 0 1 1 1
# K15:	0 0 0 1 1 0 0 1 0 0 1 0 1 1 0 0 1 0 0 0 1 1 0 0 1 0 1 0 0 1 1 1 0 0 0 0 0 0 1 1 1 0 0 0 0 0 1 0
# K16:	0 1 0 1 0 0 0 1 0 0 1 0 1 1 0 0 1 0 0 0 1 1 0 0 0 0 0 1 0 1 1 1 0 0 1 0 0 0 1 1 1 1 0 0 0 0 1 0
#
# *******************************************************************************************************

def loop_key(key):
    C0=key[0:28]
    D0=key[28:56]
    key=[]
    for i,j in zip(LOOP,range(0,16)):
        C0=C0[i:28]+C0[0:i]
        D0=D0[i:28]+D0[0:i]
        key.append([])
        key[j]=exchange(PC2,C0+D0)
    return key



#***********************************************************************************************************
# loop 16 times to encrypt strings (8 bytes a group)
# for example:
# input string: 'hello'
# then we get:

# 11001101 00111100 01010111 11111100 11110110 11100011 10101111 11101001
# hex: 6eacdd5b95bbe7eb

#************************************************************************************************************

def loop_text(text,key,result,round=16,mode=None):

    L=text[0:32]
    R=text[32:64]

    for k,r in zip(key,range(0,round)):
        temp=R
        #round_table.append([])
        #round_table[r].append([L,R])
        R=exchange(E,R)
        S_table_input=R
        R=xor(R,k)
        #S_table_input=R
        R=S_exchange(R)

        result.append([S_table_input,R])

        R=exchange(P,R)

        R=xor(R,L)
        L=temp

    # you can show round_table and get every round bin data for debug
    # for i in round_table:
    #   for j in i:
    #     print ...

    return R+L






#================================================================
# the DES main class here
# initDES to learn DES and also
# use initS to generate diff_table 
# then use differential analysis to attack DES

class DES(object):

    diff_table=[]
    key=[]
    enc=[]
    hex_dec=[]
    hex_set=[]
    S_table_inout=[]
    dec=''
    gcount=0
    round=0

    def __doc__(self):
        print '\nthis class is used for attack DES (env Linux)'
        print 'Author: fanda    mail:1278466220@qq.com\n'
        print 'use it by \'from des import DES\''
        print 'first init a class by \'xxx = DES()\' and then use the method:\n'
        print 'initS()              *used to init the diff-table*'
        print 'display(flag)        *used to display table or generate to  file (flag==0 > stdout,flag==1 > file)*'
        print 'initDES()            *used to generate DES key and get the key at every step'
        print 'show(flag1,flag2)    *only can be called after initDES() get all information about encrypt'
        print 'auto_diff_analy()    *can be called to auto-use differential-analysis attack\n'




    # get the input string and spilit by 8 bytes a group
    # then convert to binary
    # initialize the DES encryption and decryption 
    # ready to do differential analysis

    def initDES(self,string='',passwd='',round=16):
        
        self.key=[]                 # key
        self.enc=[]                 # string to be encrypted
        self.enc_bak=[]             # store the encrypted bin-stream
        self.hex_dec=[]             # decrypted hex string
        self.dec=''                 # decrypted string
        self.hex_set=[[],[]]             # hex stream
        self.S_table_inout=[]       # recv the S-boxes' input and output
        self.gcount=0                    # align group size
        self.round=round            # encrypt round count



        #string='Hello,world!'
        #passwd='xxxxxxxx'

        #*******************************************************************
        # here to format the input and key
        # key in DES will not greater than 8 bytes
        # the input can be anything 
        # here use '\x20'(space) to padding 
        #*****************************************************************

        if len(string)==0:
            return 'usage: \'initDES(<string>,<key>)\''
        else:
            self.gcount=len(string)/8 if len(string)%8==0 else (len(string)/8)+1
            string+= (8*self.gcount-len(string))*'\x20'
            for i in range(0,len(string)/8):
                self.enc.append([])
                self.enc_bak.append([])
                for j in string[i*8:(i+1)*8]:
                    for k in c2bin(j):
                        self.enc[i].append(k)

        if len(passwd)==0:
            passwd='\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            passwd=passwd+'\x00'*(8-len(passwd)) if len(passwd)<8 else passwd[0:8]
        for i in passwd:
            b=c2bin(i)
            for j in b:
                self.key.append(j)

        #==================================================================
        # now the input and key are both ready
        # DES encrypt and decrypt following:


        # PC1-exchange
        self.key=exchange(PC1,self.key)


        # LOOP and PC2-exchange
        self.key=loop_key(self.key)
        #================================================================
        # and now key has been generated


        # Then start to encrypt
        # support round define
        #==============================================================
        # IP exchange for input
        for i in range(0,len(self.enc)):
            self.enc[i]=exchange(IP,self.enc[i])


        # round encrypt group by group
        for i in range(0,len(self.enc)):
            self.S_table_inout.append([])
            self.enc[i]=loop_text(self.enc[i],self.key[0:round],self.S_table_inout[i],round,ENCRYPT)
            self.enc[i]=exchange(IP1,self.enc[i])

        # make string more readable
        for i in self.enc:
            s=hex(int(''.join(i),2))[2:]
            if s[-1]=='L':
                s=s[:-2]
            #s='0'*(16-len(s))+s
            self.hex_set[0].append(s)

        # bake-up the enc
        for i in range(0,len(self.enc)):
            self.enc_bak[i]=self.enc[i]


        # here to decrypt
        for i in range(0,len(self.enc)):
            self.enc[i]=exchange(IP,self.enc[i])

        # just reverse the key to decrypt
        for i in range(0,len(self.enc)):
            self.hex_dec.append(loop_text(self.enc[i],self.key[round-1::-1],[],round,DECRYPT))

        # make result readable
        for i in range(0,len(self.hex_dec)):
            self.hex_dec[i]=exchange(IP1,self.hex_dec[i])
            s=hex(int(''.join(self.hex_dec[i]),2))[2:]
            if s[-1]=='L':
                s=s[:-2]
            s='0'*(16-len(s))+s
            self.hex_set[1].append(s)
            self.dec+=binascii.a2b_hex(s)
    

        # encrypt and decrypt end
        #=============================================================

    


    # then we use show to get every round data and analysis it!
    #===================================================================
    # I just code it casually :)
    # so if you need something stronger, edit it!

    def show(self,fkey=0,fbox=0):

        if len(self.hex_set)==0:
            return 'you should show afrer initDES(...)'

        n=0
        print 'encrypt string(hex):'
        print self.hex_set[0]
        for i in self.enc_bak:
            print 'group '+str(n)+':'
            for j in i:
                print j,
            print 
            n+=1


        if(fkey==1):
            print 'the key:'
            for i,n in zip(self.key,range(1,17)):
                print 'K'+str(n)+':\t',
                for j in i:
                    print j,
                print
            print 
        

        if(fbox==1):
            for g in range(0,len(self.S_table_inout)):
                print 'Group '+str(g+1)+':'
                for r in range(0,self.round):
                    print 'round '+str(r+1)+':'
                    print 'input: \t\t\toutput:'
                    for c in range(0,8):
                        for i in self.S_table_inout[g][r][0][c*6:(c+1)*6]:
                            print i,
                        print '\t----------->\t',
                        for j in self.S_table_inout[g][r][1][c*4:(c+1)*4]:
                            print j,
                        print 
                print




        n=0
        print '\n\ndecrypt string(hex):'
        print self.hex_set[1]
        for i in self.hex_dec:
            print 'group '+str(n)+':'
            for j in i:
                print j,
            print 
            n+=1

        print '\ndecrypt string:'
        print self.dec
        print




    # end the generate DES part
    #================================================

    # now learn to use differential analysis to attack the DES
    #*******************************************************************
    # the differential table will be generated like:
    #
    # diff_table =  [   < S-boxes >             ]
    #               [   < input xor value >     ]
    #               [   < output xor value >    ]



    def initS(self):
        for i in xrange(8):
            self.diff_table.append([])
            for j in xrange(0x40):
                self.diff_table[i].append([])
                for k in xrange(0x10):
                    self.diff_table[i][j].append([])

        for i in range(0,8):
            for j in range(0,64):
                for k in range(0,64):
                    self.diff_table[i][j^k][S[i][h(j)][l(j)]^S[i][h(k)][l(k)]].append(k)


    # hard to understand, but just generated the differential table
    #************************************************************************
    # use auto-differential analysis
    # here we store the input/output by a 3-dimension array design:
    #
    #           group
    #   round  _________________________
    #          |________________________|
    #          |________________________|
    #          |________________________|
    #          |...............         |
    #          |....................    |
    #          |                        |
    #          |________________________|
    #
    #
    #   while key made up with 8 pieces 
    #   each piece is a 6-bit stream
    #   also the third dimension of array
    #=================================================================

    
    def auto_diff_analy(self):

        if len(self.diff_table)==0:
            return 'call initS() first'
        if len(self.S_table_inout)==0:
            return 'call initDES() first'

        p_set=[]
        possible_set=[]
        S1_input=[]
        S1_output=[]

        print 'using auto differential analysis( with know all S-boxes\' input and output )...'

        for r in range(0,self.round):
            p_set.append([])
            S1_input.append([])
            S1_output.append([])
            for i in range(0,self.gcount/2):
                for j in range(0,8):
                    p_set[r].append([])
                    S1_input[r].append([])
                    S1_output[r].append([])
                    S1_input1=int(''.join(self.S_table_inout[i*2][r][0][j*6:(j+1)*6]),2)
                    S1_input2=int(''.join(self.S_table_inout[i*2+1][r][0][j*6:(j+1)*6]),2)
                    S1_output1=int(''.join(self.S_table_inout[i*2][r][1][j*4:(j+1)*4]),2)
                    S1_output2=int(''.join(self.S_table_inout[i*2+1][r][1][j*4:(j+1)*4]),2)
                    p_set[r][j].append(self.diff_table[j][S1_input1^S1_input2][S1_output1^S1_output2])
                    S1_input[r][j].append([S1_input1,S1_input2])
                    S1_output[r][j].append([S1_output1,S1_output2])

        #======================================================
        # we've gotten the possible input's differential table here
        # then we XOR the every item in the table with the inputs
        # just one of inputs is enough for S<x> box 2-group


        for s,i in zip(p_set,range(0,self.round)):
            possible_set.append([])
            for j in range(0,self.gcount/2):
                for k in range(0,8):
                    possible_set[i].append([])
                    possible_set[i][k].append(list(S1_input[i][k][j][0]^z for z in s[k][j]))

        
        #=====================================================
        # then we are closing the set of possible key
        # use set's '&' to get the closely set
        # and then if we want to know the exactly key
        # we must know more message and plain text


        the_set=[]
        if len(possible_set[0][0])==0:
            print 'set of K:None'
            print 
            return ''
        else:
            for i in range(0,self.round):
                the_set.append([])
                for p in range(0,8):
                    temp=set(possible_set[i][p][0])
                    for j in possible_set[i][p]:
                        temp=temp&set(j)
                    the_set[i].append(temp)


        for i,j in zip(the_set,range(0,self.round)):
            print 'possible set of K'+str(j+1)+':'
            for j,r in zip(i,range(0,8)):
                print str(r*6)+'-'+str((r+1)*6)+':',
                for k in j:
                    print hex(k)[2:],
                print
            print
        print 





    # show a set of possible key value
    #===============================================================
    # display to standard output or record it to the file

    def display(self,iswrite=False):
        if self.diff_table==[]:
            print 'please use initS() method before display!'
        else:    
            if iswrite==True:
                f=open('table.txt','w')
            else:
                f=open('/dev/stdout','w')
            for i in range(0,8):
                print >>f,'S'+str(i+1)+':'
                for j in range(0,64):
                    print >>f,'xor value '+hex(j)[2:]+':'
                    for k in range(0,0x10):
                        self.diff_table[i][j][k].sort()
                        if self.diff_table[i][j][k]!=[]:
                            print >>f,hex(k)[2:]+':',
                            for l in self.diff_table[i][j][k]:
                                print >>f,hex(l)[2:],
                            print >>f
                    print >>f
                print >>f,'\n\n\n\n'
            f.close()


if __name__ == '__main__':
    
    if len(sys.argv)==1:
        DES().__doc__()
    else:
        print 'hum?'

    # here is the demo to use:
    # just support 1 round differential analysis
    # maybe use python shell to import it will be better :)

    #a=DES()
    #a.initDES('hello,world world world and world','0123456789',5)
    #a.show(1,1)

    #a.initS()
    #a.auto_diff_analy()

