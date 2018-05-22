#include <stdio.h>


int main()
{
	unsigned char key_string[]= "\x10\x18\x43\x14\x15\x47\x40\x17"
													"\x10\x1D\x4B\x12\x1F\x49\x48\x18"
													"\x53\x54\x01\x57\x51\x53\x05\x56"
													"\x5A\x08\x58\x5F\x0A\x0C\x58\x09\x00";
	unsigned int count,temp1,temp2,temp4,a1,a2;
	unsigned char ch=0x20;
	unsigned char*ptr=key_string;
	count=0x20;
	while(1)
	{
		
		a1=~(ch&count);
		temp1=unsigned char(a1);
		
		a2=a1;
		a1=~(count&a2);
		temp2=(unsigned char)a1;
		a1=~(a2&ch);
		
		a2=a1;
		a1=0xffffff00+temp2;
		a1=~(a1&a2);
		temp4=(unsigned char)a1;
		if(temp4!=*ptr)
			ch++;
		else
		{
			printf("%c",ch);
			ch=0x20;
			ptr++;
			count++;
			
			//break;
			if(!(*ptr))
				break;
		}
	}
	
	return 0;
}