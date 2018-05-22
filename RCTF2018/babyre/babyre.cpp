#include <stdio.h>


#define LODWORD(x)  (*((unsigned int*)&(x)))
#define HIDWORD(x)  (*((unsigned int*)&(x)+1))

unsigned __int64 key[]={
0x70573EFEB80C91FE,
0x7F7A8193BEED92AE,
0x90347C6C7390C17B,
0xAA7A15DFAA7A15DF,
0x153F1A32526BA076,
0x7D8AA463545C15AD,
0xFBCB7AA0526BA076,
0x9C5132667D8AA463,
0x6D7DF3E1526BA076,
0x9C513266AA7A15DF,
0x9323BC071EDC3864,
0xFBCB7AA07D8AA463,
0x526BA076153F1A32,
0xAA7A15DFF5650025,
0xB13AD8881EDC3864,
0
};

int main()
{
	unsigned int ptr_string;
	unsigned __int64 constants=0x1d082c23a72be4c1;
	unsigned __int64 temp;
	int i=0;
	unsigned int* ptr_key=(unsigned int*)key;
	
	char* dir="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	while(1)
	{
		i=0;
		while(1)
		{
			ptr_string=dir[i];
			for (int j = 0; j <= 0x20F; ++j)
  		{
  	  	temp = constants >> (j & 0x1F);
  		  if ( j & 0x20 )
  		    LODWORD(temp) = HIDWORD(temp);
	  	  ptr_string = (ptr_string >> 1) ^ (((unsigned int)temp ^ ptr_string ^ (ptr_string >> 16) ^ (0x5C743A2E >> (((ptr_string >> 1) & 1) + 2 * (2 * (((ptr_string >> 20) & 1) + 2 * (2 * (ptr_string >> 31) + ((ptr_string >> 26) & 1))) + ((ptr_string >> 9) & 1))))) << 31);
	  	}
	  	if(ptr_string==*ptr_key)
	  		break;
			i++;
		}
		printf("%c",dir[i]);
		ptr_key++;
		if(!(*ptr_key))
			break;
	}
	return 0;
}
