#!/bin/python

'''
  signed __int64 result; // rax

  *temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (unsigned __int16)temp2 & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FFui64 | ((temp1 & 0xFF000000000000i64 | temp2 & 0xFF0000000000i64 | ((temp1 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)temp2 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  result = 0xFF00000000000000i64;
  *temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000ui64 | (((unsigned __int16)temp1 & 0xFF00 | ((unsigned __int64)(unsigned __int8)temp1 << 24)) << 24) | ((temp2 & 0xFF000000000000i64 | ((temp1 & 0xFF0000000000i64 | ((temp2 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)temp1 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  return result;



temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (temp2&0xffff) & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FF | ((temp1 & 0xFF000000000000 | temp2 & 0xFF0000000000 | ((temp1 & 0xFF00000000 | (((temp2&0xffffffff)&0xffffffffffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8)
temp4&=0xffffffffffffffff

temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000 | (((temp1&0xffff) & 0xFF00 | (((temp1&0xff)&0xffffffffffffffff) << 24)) << 24) | ((temp2 & 0xFF000000000000 | ((temp1 & 0xFF0000000000 | ((temp2 & 0xFF00000000 | ((temp1&0xffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8);
temp3&=0xffffffffffffffff
'''

def encry1120(temp1,temp2,temp3,temp4):

    temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (temp2&0xffff) & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FF | ((temp1 & 0xFF000000000000 | temp2 & 0xFF0000000000 | ((temp1 & 0xFF00000000 | (((temp2&0xffffffff)&0xffffffffffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8)
    temp4&=0xffffffffffffffff

    temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000 | (((temp1&0xffff) & 0xFF00 | (((temp1&0xff)&0xffffffffffffffff) << 24)) << 24) | ((temp2 & 0xFF000000000000 | ((temp1 & 0xFF0000000000 | ((temp2 & 0xFF00000000 | ((temp1&0xffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8);
    temp3&=0xffffffffffffffff

    return temp1,temp2,temp3,temp4



def decry1120(temp1,temp2,temp3,temp4):

    temp4 -= temp2 & 0xFF0000 | (((temp2 << 24) | (temp2&0xffff) & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FF | ((temp1 & 0xFF000000000000 | temp2 & 0xFF0000000000 | ((temp1 & 0xFF00000000 | (((temp2&0xffffffff)&0xffffffffffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8)
    temp4&=0xffffffffffffffff

    temp3 -= temp1 & 0xFF0000 | temp2 & 0xFF00000000000000 | (((temp1&0xffff) & 0xFF00 | (((temp1&0xff)&0xffffffffffffffff) << 24)) << 24) | ((temp2 & 0xFF000000000000 | ((temp1 & 0xFF0000000000 | ((temp2 & 0xFF00000000 | ((temp1&0xffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8);
    temp3&=0xffffffffffffffff

    return temp1,temp2,temp3,temp4

