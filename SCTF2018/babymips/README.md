# SCTF2018 babymips
## Author: 文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>重感冒躺尸了一星期，这几天才有了一点精神，就把sctf的题再拿出来做一做，mips还是头疼啊，不过好在这题加密不复杂。</font><br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>先用qemu跑了一下失败了，那算了懒得搞了，IDA硬刚吧。首先很明显长度为0x26，以下是一段异或加密：</font><br>

```mips
lw      $v0, 0x880+var_858($fp)
addiu   $v1, $fp, 0x880+var_8
addu    $v0, $v1, $v0
lb      $v1, -0x838($v0)
lw      $v0, 0x880+var_858($fp)
andi    $v0, 0xFF
addiu   $v0, 1
andi    $v0, 0xFF
sll     $v0, 24
sra     $v0, 24
xor     $v0, $v1, $v0
sll     $v1, $v0, 24
sra     $v1, 24
lw      $v0, 0x880+var_858($fp)
addiu   $a0, $fp, 0x880+var_8
addu    $v0, $a0, $v0
sb      $v1, -0x838($v0)
lw      $v0, 0x880+var_858($fp)
addiu   $v0, 1
sw      $v0, 0x880+var_858($fp)
b       loc_400E60
nop
```

```C
//解密相当于
for(int i=0;i<0x26;i++)
  flag[i]^=i+1;
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>继续往下走，有一个奇怪的函数sub_400A90，对一段密文进行异或解密。接下来坑的是他把这段解密后的密文地址覆盖掉了原来的memcmp函数，意思就是从密文处开始执行了，所以我们把解密后的密文dump出用IDA强行分析一波：</font><br>

```C
//decode first,
//then dump opcode file
void decrypt()
{
	FILE* fp;
	fp=fopen("1.txt","wb");
	unsigned char* ptr=(unsigned char*)key;
	unsigned char d,e,f=0;
	for(int j=0;j<0x1d8;j++)
	{
		
		for(int i=0;i<8;i++)
		{
			e=(*ptr>>i)&1;
			f|=((e<<(7-i))&0xffffff);
		}
		
		fwrite(&f,1,1,fp);
		d=0;e=0;f=0;
		if((j+1)%8==0)
			puts("");
		ptr++;
	}
	fclose(fp);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>看一下解密没问题，去掉txt后缀，用IDA加载，选择MIPS little endian类型后再打开，然后选择下面的数据右键code，force强行分析就可以得到反汇编代码了。首先:</font><br>

```mips
loc_68:                                  
                li      $v0, 5
                sw      $v0, 0x24($fp)

loc_70:                                  
                lw      $v0, 0x24($fp)
                slti    $v0, 0x25  # '%'
                beqz    $v0, loc_C0
                nop
                lw      $v0, 0x24($fp)
                lw      $v1, 0x1C($fp)
                addu    $v0, $v1, $v0
                lw      $v1, 0x24($fp)
                lw      $a0, 0x1C($fp)
                addu    $v1, $a0, $v1
                lb      $v1, 0($v1)
                xori    $v1, 0x30
                sll     $v1, 24
                sra     $v1, 24
                sb      $v1, 0($v0)
                lw      $v0, 0x24($fp)
                addiu   $v0, 1
                sw      $v0, 0x24($fp)
                b       loc_70
                nop
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>解密代码：</font><br>

```C
for(int i=5;i<0x25;i++)
  flag[i]^=0x30;
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>还有一段：</font><br>

```mips
loc_C0:                                 
                li      $v0, 0x66746373
                sw      $v0, 0x2C($fp)
                sb      $zero, 0x30($fp)
                li      $v0, 5
                sw      $v0, 0x28($fp)

loc_D8:                                 
                lw      $v0, 0x28($fp)
                slti    $v0, 0x25  # '%'
                beqz    $v0, loc_160
                nop
                lw      $v0, 0x28($fp)
                lw      $v1, 0x1C($fp)
                addu    $v1, $v0
                lw      $v0, 0x28($fp)
                lw      $a0, 0x1C($fp)
                addu    $v0, $a0, $v0
                lb      $a0, 0($v0)
                lw      $v0, 0x28($fp)
                addiu   $a1, $v0, -5
                li      $v0, 0x80000003
                and     $v0, $a1, $v0
                bgez    $v0, loc_130
                nop
                addiu   $v0, -1
                li      $a1, 0xFFFFFFFC
                or      $v0, $a1
                addiu   $v0, 1
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>解密代码如下：</font><br>

```C
unsigned char k[4]={0x73,0x63,0x74,0x66};
for(int i=5;i<0x25;i++)
	flag[i]^=k[(i-5)%4];
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>做完了:)</font><br>

最终脚本
=======

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int key[0x100]={
0xE4BDFF03, 0xF5FD003C, 0xF57D001C, 0xC0050FA4, 0x3C380042,
0xE439050E, 0xF53D0008, 0xF5230038, 0xF5A30018, 0xF5630012,
0xF1410101, 0x31420000, 0xF543002C, 0xF1430038, 0x80200EA,
0, 0xF1430018, 0x802002A, 0, 0xF1C30012, 0x24400064,
0x8460020, 0, 0x24400080, 0x8000072, 0, 0x244000A0,
0xF5430024, 0xF1430024, 0x144200A4, 0x8020088, 0,
0xF1430024, 0xF1C30038, 0x460884, 0xF1C30024, 0xF1230038,
0xC11884, 0x1C60000, 0x1CC6000C, 0xC07800, 0xC078C0,
0x5C20000, 0xF1430024, 0x24420080, 0xF5430024, 0x800FFB7,
0, 0x3C40662E, 0x2C42C6CE, 0xF5430034, 0xC503000C,
0x244000A0, 0xF5430014, 0xF1430014, 0x144200A4, 0x80200F8,
0, 0xF1430014, 0xF1C30038, 0x461884, 0xF1430014,
0xF1230038, 0x410884, 0x1220000, 0xF1430014, 0x24A2FFDF,
0x3C400100, 0x2C4200C0, 0x450824, 0x208200A0, 0,
0x2442FFFF, 0x24A0FF3F, 0xA208A4, 0x24420080, 0xE4A3001C,
0x450884, 0x142FF2F, 0x410864, 0x406800, 0x4068C0,
0x5460000, 0xF1430014, 0x24420080, 0xF5430014, 0x800FFFB,
0, 0x24600064, 0xF1A30038, 0x3C400082, 0x2422041C,
0xF141012E, 0x213A4, 0xC0041F90, 0, 0xF13B0008, 0x28020020,
0, 0x8A4, 0x8000040, 0, 0x24400080, 0xF1C10101, 0xF123002C,
0x31C60000, 0x8C100A0, 0, 0xF1410136, 0x213A4, 0xC0041F90,
0, 0xC00317A4, 0xF1FD003C, 0xF17D001C, 0xE4BD0002,
0xC0070010, 0,0,
	};



unsigned char string[0x30]={
0x72,0x61,0x77,0x62,0x7E,7,0x35,0x2E,
0x26,0x24,0x31,0x38,0x28,0x12,0x35,7,
0x18,0x22,0x2F,0xF,0x26,0x34,0x71,0x25,
0x10,0x20,0x27,0x37,0x24,0x32,0x23,0xB,
0x18,0xE,0x1F,0xF,0x52,0x5B,0,
0,
};

//get the opcode file
void decrypt()
{
	FILE* fp;
	fp=fopen("1.txt","wb");
	unsigned char* ptr=(unsigned char*)key;
	unsigned char d,e,f=0;
	for(int j=0;j<0x1d8;j++)
	{
		
		for(int i=0;i<8;i++)
		{
			e=(*ptr>>i)&1;
			f|=((e<<(7-i))&0xffffff);
		}
		
		fwrite(&f,1,1,fp);
		d=0;e=0;f=0;
		if((j+1)%8==0)
			puts("");
		ptr++;
	}
	fclose(fp);
}


int main()
{
	//decrypt();
	
	unsigned char flag[0x30]={0,};
	memcpy(flag,string,0x26);
	unsigned char* ptr=flag;
	
	for(int i=0;i<0x26;i++)
	{
		*ptr^=(i+1);
		ptr++;
	}
	
	ptr=flag;
	
	ptr+=5;
	for(int i=5;i<0x25;i++)
	{
		*ptr^=0x30;
		ptr++;
	}
	
	ptr=flag;
	unsigned char k[4]={0x73,0x63,0x74,0x66};
	for(int i=5;i<0x25;i++)
	{
		*(ptr+i)^=k[(i-5)%4];
	}
	
	printf("%s\n",flag);
	//sctf{Babymips_iS_so_ea5y_yoooooooooo!}
	
	return 0;
}
```
