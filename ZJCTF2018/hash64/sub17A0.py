#!/bin/python
from sub1120 import *


def encry17A0(size,flag):

    table_ptr=[]

    if flag==1:
        table_ptr=[\
        0x0CF0C0CBED5EDF48,
        0x1B37052812A528D2,
        0x213FAF142052526F,
        0x6B1147AEAE892205,
        0x063C052363821F70,
        0x5BA1C56E3EDEC22B,
        0xD91FB9753CA5209B,
        0x08233AB8F8F96C5F,
        0x1BE6D5D5FE4CCE2F,
        0x24093822299F31D0,
        0x33198A2E03707344,
        0x443F6A8885A308D3,
        0x5BD39E10CB0EF593,
        0x60ACF169B5F18A8C,
        0x7E5466CF34E90C6C,
        0x852821E638D01377]
    else:
        table_ptr=[\
        0x0CF0C0C5ED5EDF42,
        0x1B37052212A528CC,
        0x213FAF0E20525269,
        0x6B1147A8AE8921FF,
        0x8C18F014C18E087D,
        0xB96E8715ACFB7B08,
        0xD7647EE56CF29482,
        0xE0208CEA7FE3E5B1,
        0x1BE6D5D5FE4CCE2F,
        0x24093822299F31D0,
        0x33198A2E03707344,
        0x443F6A8885A308D3,
        0x5BD39E10CB0EF593,
        0x60ACF169B5F18A8C,
        0x7E5466CF34E90C6C,
        0x852821E638D01377]
    
    
    '''
    count= 4;
    do
      {
        v13 = *(table_ptr - 8);
        v14 = *(table_ptr - 4) + *table_ptr + *(_QWORD *)&v11[(_QWORD)table_ptr - 64];
        v15 = (unsigned int)(*((_DWORD *)table_ptr - 8) + *(_DWORD *)table_ptr + *(_DWORD *)&v11[(_QWORD)table_ptr - 64]);
        v16 = *(table_ptr - 8) >> 32;
        *(table_ptr - 4) = v14;
        ++table_ptr;
        *(table_ptr - 1) ^= v16 * v15;
        v17 = table_ptr[3];
        *(table_ptr - 9) = v13 + v17;
        table_ptr[3] = v17 ^ (unsigned int)(v13 + v17) * (v14 >> 32);
        --v12;
      }
      while ( v12 );
    '''
    
    Size=size
    i=8
    for j in range(4):
        temp1=table_ptr[i-8]
        temp2=(table_ptr[i-4]+table_ptr[i]+Size[i-8])&0xffffffffffffffff
        temp3=((table_ptr[i-4])+(table_ptr[i]&0xffffffff)+Size[i-8])&0xffffffff
        temp4=table_ptr[i-8]>>32
        table_ptr[i-4]=temp2
    
        i+=1
        table_ptr[i-1]^=(temp3*temp4)&0xffffffffffffffff
        temp5=table_ptr[i+3]
        table_ptr[i-9]=(temp1+temp5)&0xffffffffffffffff
        table_ptr[i+3]=(temp5^((temp1+temp5)&0xffffffff)*(temp2>>32))&0xffffffffffffffff
    
    
    
    table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0]=encry1120(table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0])
    table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2]=encry1120(table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2])
    table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4]=encry1120(table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4])
    table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6]=encry1120(table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6])
    
    
    return table_ptr
