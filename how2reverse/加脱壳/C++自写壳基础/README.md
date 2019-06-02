> 环境：win7+VS2010+010Editor

&emsp;&emsp;<font size=2>很幸运在看雪看到了几篇非常好的自写壳入门文章，这篇文章就是学习上面的一篇[C++写壳详解之基础篇](https://bbs.pediy.com/thread-250960.htm)，然后讲解之的。首先建议参考原文，手动添加一个壳上去，然后你就对加壳的原理有了一个非常直观的理解，再往下看会轻松一些，至于手动加壳的部分原文已经写的非常详细了，这里就不赘述（用010Editor的EXE模版可以非常方便的对PE结构进行修改）。</font></br>

&emsp;&emsp;<font size=2>首先建议按照原文利用010editor手动修改PE加个最简单的壳上去，完了之后你就会对壳的原理有了一个比较直观的理解，然后我们再来看如何用C++这种自动化的方式添加自定义代码进去，我们只看加壳相关的函数，无关紧要的函数就请大家自行分析：</font></br>

&emsp;&emsp;<font size=2>加壳一般都是新建一个节区，然后把壳的代码放在里面，然后把程序的入口点设置为壳的节区，因此先看加节区的部分：</font></br>

```C
//2.添加一个新区段
void AddSection(char*& pTarBuff, int& nTarSize,
	const char* pSecName, int nSecSize)
{
	//区段数目加1
	int n = GetFileHeader(pTarBuff)->NumberOfSections++;
	PIMAGE_SECTION_HEADER pSec = GetLastSecHeader(pTarBuff);

	DWORD dwFileAlig = GetOptHeader(pTarBuff)->FileAlignment;
	DWORD dwMemAlig = GetOptHeader(pTarBuff)->SectionAlignment;
	//设置新区段信息
	memcpy(pSec->Name, pSecName, 8);
	pSec->Misc.VirtualSize = nSecSize;
	pSec->SizeOfRawData = Aligment(nSecSize, dwFileAlig);
	//内存的RVA
	pSec->VirtualAddress = (pSec - 1)->VirtualAddress +
		Aligment((pSec - 1)->SizeOfRawData, dwMemAlig);
	//文件偏移要注意，把之前的文件偏移对齐；
	pSec->PointerToRawData = Aligment(nTarSize, dwFileAlig);
	pSec->Characteristics = 0xE00000E0;
	//映像大小,注意要进行内存对齐
  // 	GetOptHeader(pTarBuff)->SizeOfImage = pSec->VirtualAddress +
  // 		Aligment(nSecSize,dwMemAlig);
	GetOptHeader(pTarBuff)->SizeOfImage = 
		Aligment(pSec->VirtualAddress + pSec->SizeOfRawData, dwMemAlig);


	//增加文件大小
	int nNewSize = pSec->SizeOfRawData + pSec->PointerToRawData;
	char* pNewFile = new char[nNewSize];
	memset(pNewFile, '\x90', nNewSize);
	memcpy(pNewFile, pTarBuff, nTarSize);
	delete[] pTarBuff;
	pTarBuff = pNewFile;
	nTarSize = nNewSize;
}
```

&emsp;&emsp;<font size=2>原文作者代码写的非常好，自定义函数直接顾名思义就行了，然后根据注释也不难理解，如果你实践过手动加壳的话这里应该是非常容易看懂的。添加完节区之后，我们就有了这样一块空间供我们放壳代码了，代码怎么来？当然是编译链接后生成的了，也就是说我们把代码写在另一个文件里生成后读取出来写入我们的节区里。我们暂且先不管这一个文件怎么写怎么生成，先假设我们已经有了这一个文件，代码都在其中的".text"节区里，那么我们要做的就是把这个".text"里的代码移植到我们的"壳"节区里，为了不破坏壳代码里的函数调用，我们不可避免的要进行**重定向修复**！关于重定向表的作用这一篇文章讲的也是非常的好：[PE文件格式之重定位表](https://bbs.pediy.com/thread-246759.htm)。</font></br>

&emsp;&emsp;<font size=2>重定向表里记录的都是函数的偏移地址，也就是说`func_addr=ImageBase+VirtualAddress+reloc_Offset`。如果我们直接把代码复制到"壳”节区里，因为我们没有根据重定向表（注意是根据重定向表修复函数地址而不是修复重定向表本身）修复代码中原来的函数地址，那么代码就完全乱了。修复代码如下：</font></br>

```C
//3.修复stub的重定位
void FixStubReloc(char* hModule,DWORD dwNewBase,DWORD dwNewSecRva)
{
	//获取重定位va
	auto pReloc = (PIMAGE_BASE_RELOCATION)
		(GetOptHeader(hModule)->DataDirectory[5].VirtualAddress
			+ hModule);

	//获取.text区段的Rva
	DWORD dwTextRva = (DWORD)GetSecHeader(hModule, ".text")->VirtualAddress;

	//修复重定位
	while (pReloc->SizeOfBlock)
	{
		struct TypeOffset 
		{
			WORD offset : 12;
			WORD type : 4;
		};
		TypeOffset* pTyOf = (TypeOffset*)(pReloc + 1);
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		for (size_t i = 0; i < dwCount; i++)
		{
			if(pTyOf[i].type != 3)
				continue;
			//要修复的Rva
			DWORD dwFixRva = pTyOf[i].offset + pReloc->VirtualAddress;
			//要修复的地址
			DWORD* pFixAddr = (DWORD*)(dwFixRva + (DWORD)hModule);

			DWORD dwOld;
			VirtualProtect(pFixAddr, 4, PAGE_READWRITE, &dwOld);
			*pFixAddr -= (DWORD)hModule; //减去原始基址
			*pFixAddr -= dwTextRva;      //减去原始代码段Rva
			*pFixAddr += dwNewBase;      //加上新基址
			*pFixAddr += dwNewSecRva;    //加上新Rva
			VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		}
		//指向下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)
			((DWORD)pReloc + pReloc->SizeOfBlock);
	}		
}
```

&emsp;&emsp;<font size=2>修复完了之后原先的代码定义的函数在壳中也能正常调用了，只要设置一下OEP为新的壳节区就行了。那么这就结束了吗？还没有，壳节区的代码也不是随便写什么都能跑的。设想一下，如果在写壳代码文件的时候你用到了API，API的调用是根据IAT表获得的函数地址，我们先前根据重定向表修复的是自定义函数的地址，而NAT函数地址是写死的，是系统给的。如果IAT表里没有我们想要的函数怎么办（何况壳一般还会加密IAT表，那就更不可能调用的起来了）？我们自己实现`GetProcAddress`，有了`GetProcAddress`我们就可以配合`LoadLibrary`调用任何函数（`LoadLibrary`怎么来？`GetProcAddress`啊）。</font></br>

&emsp;&emsp;<font size=2>`kernel32.dll`这个库文件是每个程序都会装载的，`GetProcAddress`就在里面，我们只要在里面搜索就能得到了，首先取得`kernel32.dll`（取得kernel32首地址有三种方式，这里选择初始化顺序方法）首地址：</font></br>

```
		push esi;
		mov esi, fs:[0x30];   //得到PEB地址
		mov esi, [esi + 0xc]; //指向PEB_LDR_DATA结构的首地址
		mov esi, [esi + 0x1c];//一个双向链表的地址
		mov esi, [esi];       //得到第2个条目kernelBase的链表
		mov esi, [esi];       //得到第3个条目kernel32的链表(win10系统)
		mov esi, [esi + 0x8]; //kernel32.dll地址
		mov g_hKernel32, esi;
		pop esi;
```

&emsp;&emsp;<font size=2>然后就像对待PE文件一样根据导出表结构在内存中搜索就行了：</font></br>

```
		pushad;		
		mov ebp, esp;
		sub esp, 0xc;
		mov edx, g_hKernel32;
		mov esi, [edx + 0x3c];     //NT头的RVA
		lea esi, [esi + edx];      //NT头的VA
		mov esi, [esi + 0x78];     //Export的Rva		
		lea edi, [esi + edx];      //Export的Va
							       
		mov esi, [edi + 0x1c];     //Eat的Rva
		lea esi, [esi + edx];      //Eat的Va
		mov[ebp - 0x4], esi;       //保存Eat
							       
		mov esi, [edi + 0x20];     //Ent的Rva
		lea esi, [esi + edx];      //Ent的Va
		mov[ebp - 0x8], esi;       //保存Ent
							       
		mov esi, [edi + 0x24];     //Eot的Rva
		lea esi, [esi + edx];      //Eot的Va
		mov[ebp - 0xc], esi;       //保存Eot

		xor ecx, ecx;
		jmp _First;
	_Zero:
		inc ecx;
	_First:
		mov esi, [ebp - 0x8];     //Ent的Va
		mov esi, [esi + ecx * 4]; //FunName的Rva

		lea esi, [esi + edx];     //FunName的Va
		cmp dword ptr[esi], 050746547h;// 47657450 726F6341 64647265 7373;
		jne _Zero;                     // 上面的16进制是GetProcAddress的
		cmp dword ptr[esi + 4], 041636f72h;
		jne _Zero;
		cmp dword ptr[esi + 8], 065726464h;
		jne _Zero;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _Zero;

		xor ebx,ebx
		mov esi, [ebp - 0xc];     //Eot的Va
		mov bx, [esi + ecx * 2];  //得到序号

		mov esi, [ebp - 0x4];     //Eat的Va
		mov esi, [esi + ebx * 4]; //FunAddr的Rva
		lea eax, [esi + edx];     //FunAddr
		mov MyGetProcAddress, eax;	
		add esp, 0xc;
		popad;
```

&emsp;&emsp;<font size=2>有了这两个函数，我们就可以调用任何函数，例如我们可以调用一个MessageBox试试看：</font></br>

```C
typedef FARPROC(WINAPI*FuGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
);
typedef HMODULE(WINAPI*FuLoadLibraryExA)(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
);
typedef int(WINAPI*FuMessageBoxW)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType);

FuGetProcAddress MyGetProcAddress = 0;
FuLoadLibraryExA MyLoadLibraryExA = 0;
FuMessageBoxW MyMessageBoxW = 0;

MyLoadLibraryExA = (FuLoadLibraryExA)MyGetProcAddress(g_hKernel32, "LoadLibraryExA");
g_hUser32 = MyLoadLibraryExA("user32.dll", 0, 0);
MyMessageBoxW = (FuMessageBoxW)MyGetProcAddress(g_hUser32, "MessageBoxW");
MyMessageBoxW(0, L"大家好我是一个壳", L"提示", 0);
```

&emsp;&emsp;<font size=2>还有一个细节问题是全局变量之类的都在data段里，我们复制".text"段的话会拉下这些变量，壳代码可能也不能正常工作，所以我们要把几个重要的段拼接起来成为一个".text"段，".reloc"我们就不需要了因为我们已经修复完函数了，在C++中拼接段十分简单，用如下代码就行了，编译器会帮我们做好一切：</font></br>

```C
//把数据段融入代码段
#pragma comment(linker,"/merge:.data=.text")
//把只读数据段融入代码段
#pragma comment(linker,"/merge:.rdata=.text")
//设置代码段为可读可写可执行
#pragma comment(linker,"/section:.text,RWE")
```

&emsp;&emsp;<font size=2>所以加壳最关键的几个问题都已经在这里讲解总结了一遍了，剩下的细节问题还是自行分析源码吧，编译我是用的命令行cl，link。配置过程就是：</font></br>

- 添加VS工具包进入环境变量，我的环境是C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin;

- 启动cmd，直接输入vcvar32，这个命令会执行上述目录下的vcvar32.bat配置编译环境（为了方便我重命名为了vc32）；
- 然后就可以在任何地方使用cl和link这些编译工具了，有点像Linux的gcc :D 

&emsp;&emsp;<font size=2>生成dll与生成最终的加了壳的程序过程顺序如下（也是根据我的环境使用的命令行编译生成）：</font></br>

```
cl /c stub.cpp
link /dll stub.obj
cl main.cpp
main.exe
newfile.exe
```

&emsp;&emsp;<font size=2>最终效果如下：</font></br>

![]()