#include <stdio.h>
#include <string.h>

char key[]={
0x52,0xFD,0x16,
0xA4,0x89,0xBD,0x92,0x80,0x13,0x41,0x54,
0xA0,0x8D,0x45,0x18,0x81,0xDE,0xFC,0x95,
0xF0,0x16,0x79,0x1A,0x15,0x5B,0x75,0x1F,
0 };

int main()
{
	char buf[32];
	char*ptr;

	printf("give me flag:\n");
	scanf("%32s",buf);
	
	ptr=buf;
	for(int i=0;i<32;i++)
	  *ptr^=(32-i);

	if(!(strncmp("Q|j{g",buf,5)))
	{
	  encrypt(buf);
	  if(!(strncmp(buf,key,27)))
	    puts("got it\n");
	}
	

	return 0;
}


void encrypt(char* buf)
{
	char* ptr=buf;
	ptr+=5;
	for(int n=5;n<32;n++)
	{
	  if(n&1)
	    *ptr=(*ptr>>2)|(*ptr<<6);
	  else
	    *ptr=(*ptr<<2)|(*ptr>>6);
	}
}
