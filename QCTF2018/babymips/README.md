# QCTF2018 babymips
## Author: 文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>好久不写wp，最近开始做一些以往的题目了，潜心修炼潜心修炼，这次打击真的有点大，高三也没有过这样的大低谷，欸不扯淡了，能力要是真的提升上去了哪还用得着愁这么多呢？</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>从最近的2018QCTF开始吧，babymips主要考研的对mips汇编的了解程度，程序内部逻辑太简单不多讲，看一遍mips指令集再静下心来好好分析分析就能做出了，我差不多还原了一下源代码:</font></br>

```C
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

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后给出我的逆运算脚本：</font></br>

```python
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
    //qctf{ReA11y_4_B@89_mlp5_4_XmAn_}

	return 0;
}

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>欸怎么老是这么钟情于C呢，太费时间了。</font></br>
