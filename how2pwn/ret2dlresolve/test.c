#include <stdio.h>

#define RELPLT		0x8048278
#define DYNSYM		0x80481ac
#define DYNAMIC		0x8049620
#define BSS		0x8049728

int main()
{
	int* ptr;
	int index;

	
	// ptr pointer to .rel.plt
	ptr = (int*)RELPLT; 

	// ptr pointer to r_info of Elf32_Rel
	ptr++;

	// get index of Elf32_Sym
	index = (*ptr) >> 8;

	// ptr pointer to .dynsym
	ptr = (int*)DYNSYM;

	// pointer to Elf32_Sym
	ptr = (int*)((int)ptr + 4 * sizeof(int*) * index);

	// get st_name of Elf32_Sym
	index = *ptr;

	// pointer  to .dynamic
	ptr = (int*)DYNAMIC;

	// edit string table to .bss
	*(int*)((int)ptr + 0x44) = BSS;

	// ptr pointer to .bss
	ptr = (int*)BSS;

	// ptr pointer to "puts"
	ptr = (int*)((int)ptr + index);

	// edit "puts" to "system"
	*ptr = 0x74737973;
	*(ptr + 1) = 0x6d65;
	

	puts("/bin/sh\0");

	return 0;
}
