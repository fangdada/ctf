#include <stdio.h>

char key1[]="Q|j{g";
char key2[]={
0x52,0xFD,0x16,
0xA4,0x89,0xBD,0x92,0x80,0x13,0x41,0x54,
0xA0,0x8D,0x45,0x18,0x81,0xDE,0xFC,0x95,
0xF0,0x16,0x79,0x1A,0x15,0x5B,0x75,0x1F,
0 };

void decrypt1(char* buf)
{
	char* ptr=buf;
	for(int i=0;i<5;i++)
	{
	  *ptr=key1[i]^(32-i);
	   ptr++;
	}
}

void decrypt2(char* buf)
{
	unsigned char* ptr=buf;
	unsigned char* kptr=key2;
	ptr+=5;
	for(int i=5;i<32;i++)
	{
	  if(i&1)
	    *ptr=((*kptr<<2)&0xff)|(*kptr>>6);
	  else
	    *ptr=(*kptr>>2)|((*kptr<<6)&0xff);
	  *ptr^=(32-i);
	  ptr++;
	  kptr++;
	}
}

int main()
{
	char buf[33]={0,};
	decrypt1(buf);
	decrypt2(buf);
	printf("%s\n",buf);

	return 0;
}
