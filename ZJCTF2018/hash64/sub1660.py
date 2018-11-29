#!/bin/python

from sub1120 import *

'''
  v2 = (char *)&table1 - (char *)table;
  table_ptr = table + 8;
  v4 = 4i64;
  do
  {
    v5 = *(table_ptr - 8);
    v6 = table_ptr[4];
    v7 = *(table_ptr - 4) + *table_ptr + *(__int64 *)((char *)table_ptr + v2 - 64);
    v8 = (unsigned __int64)*(table_ptr - 8) >> 32;
    v9 = (unsigned int)(*((_DWORD *)table_ptr - 8) + *(_DWORD *)table_ptr + *(_DWORD *)((char *)table_ptr + v2 - 64));
    *(table_ptr - 4) = v7;
    ++table_ptr;
    *(table_ptr - 1) ^= v9 * v8;
    *(table_ptr - 9) = v5 + v6;
    table_ptr[3] = v6 ^ (v7 >> 32) * (unsigned int)(v5 + v6);
    --v4;
  }
  while ( v4 );
  sub_140001120(table[5], table[4], table + 1, table);
  sub_140001120(table[7], table[6], table + 3, table + 2);
  sub_140001120(table[1], *table, table + 5, table + 4);
  return sub_140001120(table[3], table[2], table + 7, table + 6);

'''

exchg=lambda (x): ((x&0xffffffff00000000)>>32)|((x&0xffffffff)<<32)


def oneloop_encry1660(table):

    table_ptr=[]
    for i in table:
        table_ptr.append(i)

    magic=[]
    magic.append(exchg(table_ptr[2]))
    magic.append(exchg(table_ptr[3]))
    magic.append(exchg(table_ptr[0]))
    magic.append(exchg(table_ptr[1]))

    i=8
    for j in range(4):
        temp1=table_ptr[i-8]
        temp2=table_ptr[i+4]

        temp3=(table_ptr[i-4]+table_ptr[i]+magic[i-8])&0xffffffffffffffff
        temp4=table_ptr[i-8]>>32
        temp5=(table_ptr[i-4]+table_ptr[i]+magic[i-8])&0xffffffff

        table_ptr[i-4]=temp3


        i+=1
        table_ptr[i-1]^=(temp4*temp5)&0xffffffffffffffff
        table_ptr[i-9]=(temp1+temp2)&0xffffffffffffffff
        table_ptr[i+3]=(temp2^(temp3>>32)*((temp1+temp2)&0xffffffff))&0xffffffffffffffff

    table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0]=encry1120(table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0])
    table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2]=encry1120(table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2])
    table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4]=encry1120(table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4])
    table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6]=encry1120(table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6])

    return table_ptr



def encry1660(table):

    result=[]
    for i in table:
        result.append(i)

    for i in range(0,4):
        result=oneloop_encry1660(result)
    
    '''
    for i in result:
        print hex(i)

    for i,j in zip(result,target):
        print i==j
        if i!=j:
            print hex(i)
            print hex(j)
    '''

    return (result[0]+result[4]+result[8]+result[12])&0xffffffffffffffff
