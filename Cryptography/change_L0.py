import binascii

IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]


table=[]

xor=lambda x,y: '0' if x==y else '1'

def c2bin(ch):
    b=bin(ord(ch))[2:]
    b='0'*(8-len(b))+b
    return b

def copy_2dimon_array(source,target):
    for i,j in zip(source,range(0,len(source))):
        target[j]=i

class des_tools(object):
    
    string=''
    final_string=''

    def change_string_L0(self,string,gcount=5):

        if gcount==0:
            print 'r u kidding me ?'
            exit()

        self.string=string
    
        group_count=(len(self.string)/8)+1 if len(self.string)%8!=0 else len(self.string)/8
        self.string=self.string+' '*(group_count*8-len(self.string)) if len(self.string)%8!=0 else self.string

        tar=[]
        tar_bak=[]
        generate=[]
        end_num=32/gcount+1
        n=0


        for i in range(0,group_count):
            tar.append([])
            tar_bak.append([])
            generate.append([])

        for i in range(0,group_count):
            for j in self.string[i*8:(i+1)*8]:
                for b in c2bin(j):
                    tar[i].append(b)

        # just copy the binary-stream array
        copy_2dimon_array(tar,tar_bak)
        copy_2dimon_array(tar,generate)


        for g in range(0,gcount):
            for i in generate:
                for j in range(0,32):
                    if j%(end_num)==n:
                        i[IP[j]-1]=xor(i[IP[j]-1],'1')
                self.final_string+=binascii.a2b_hex(hex(int(''.join(i),2))[2:])
            n+=1
            copy_2dimon_array(generate,tar)

        return self.string+self.final_string

#hello_world='hellhell'
#des_tools().change_string_L0(hello_world)
