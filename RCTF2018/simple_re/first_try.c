#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


unsigned char key[33]="quehsj_kcneop_amneuf_ieha_ehdhde";
unsigned int key_gen[13]={0,};
unsigned char flag[33]={0,};
const int len=8;
int LEN=8;
unsigned int md5_arr[]={
	0x67452301,
  0xEFCDAB89,
  0x98BADCFE,
  0x10325476,
  0
};
void init_key()
{
	unsigned int each_gen=0;
	for(int i=0;i<12;i++)
	{
		each_gen-=0x61C88647;
		key_gen[i]=each_gen;
	}
}

void print_hex(unsigned char* buf, int len)
{
  for (int i = 0; i < len; ++i)
  {
    printf("\\x%.2x", buf[i]);
  }
  printf("\n");
}


void encrypt(unsigned char* key_string,int i)
{
	unsigned int* key_ptr=(unsigned int*)key_string;
	unsigned int cc=(key_gen[i]>>2)&3;
	
	key_ptr[7]-= ((*key_ptr ^ key_gen[i]) + (key_ptr[6] ^ md5_arr[cc ^ (7 & 3)])) ^ ((4 * (*key_ptr) ^ (key_ptr[6] >> 5)) + \
								((*key_ptr >> 3) ^ 16 * key_ptr[6]));
	
	for(int j=6;j>=1;--j)
     	key_ptr[j] -= ((key_ptr[j+1] ^ key_gen[i]) + (key_ptr[j-1] ^ md5_arr[cc ^ (j & 3)])) ^ ((4 * key_ptr[j+1] ^ (key_ptr[j-1] >> 5))+((key_ptr[j+1] >> 3) ^ 16 * key_ptr[j-1]));
  key_ptr[0]-=((key_ptr[1] ^ key_gen[i]) + (key_ptr[7] ^ md5_arr[cc ^ (0 & 3)])) ^ ((4 * key_ptr[1] ^ (key_ptr[7] >> 5)) + ((key_ptr[1] >> 3) ^ 16 * key_ptr[7]));
  
}

int main()
{
	init_key();
	
	int i,j=0;
	unsigned char* key_string;
	unsigned int* ptr=(unsigned int*)flag;
	memcpy(flag,key,32);
	for ( i = 52/len + 6; i; --i )
	{
		encrypt(flag,i-1);
		//ptr=(unsigned int*)flag;
		//while(*ptr)
		//	printf("%x",*ptr++);
	}
	ptr=(unsigned int*)flag;
	while(*ptr)
		printf("%x",*ptr++);
	puts("");
	
	return 0;
}

