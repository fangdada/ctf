#include <stdio.h>
#include <stdlib.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stderr,0,2,0);
	setvbuf(stdout,0,2,0);
}

int main()
{
	void *p1,*p2,*p3,*p4;

	setbufs();
	mallopt(1,0);

	p1=malloc(0x410);
	malloc(0x20);
	p2=malloc(0x58);
	malloc(0x20);
	p3=malloc(0x420);
	malloc(0x20);

	free(p3);
	malloc(0x440);

	free(p1);
	free(p2);
	puts("now we create a largebin chunk and 2 unsortedbin chunks");
	puts("the first chunk in the unsortedbin is not fitable for the chunk we");
	puts("are going to alloc, so the first chunk will be added to largebin list");
	puts("then the second chunk will be returned to us.");
	puts("watch");

	malloc(0x58);

	//puts("if we still malloc a unfitable chunk");
	//puts("the second chunk will be added to smallbin list");
	//puts("and the first chunk will be spilited apart and still in unsortedbin list");
	//puts("BUT! Before spilit the the first chunk, there is a time the first chunk be added");
	//puts("into largebin list in int_malloc() func, we can use debug to find it");
	//malloc(0x78);


	//mm=mmap((void *)0x13370000, 0x1000, 3, 34, -1, 0);





	return 0;
}
