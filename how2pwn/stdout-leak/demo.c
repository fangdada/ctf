#include <stdio.h>
#include <stdlib.h>
#include <libio.h>

typedef unsigned long long ull;

void setbufs()
{
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}

int main()
{
	ull *p1, *p2, *p3, *p4, *p;
	_IO_FILE* pstdout;

	setbufs();

	// init the _IO_2_1_stdout_
	puts("hello,world!");
	pstdout = stdout;
	printf("&_flags:%llx\n", (ull)&pstdout->_flags);

	pstdout->_flags = (0xfbad0000 | _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING & (~_IO_NO_WRITES));
	*(unsigned char*)&pstdout->_IO_write_base = 0;
	puts("something");

	return 0;
}

/*
struct _IO_FILE {
  int _flags;
  char* _IO_read_ptr;   
  char* _IO_read_end;   
  char* _IO_read_base;  
  char* _IO_write_base; 
  char* _IO_write_ptr;  
  char* _IO_write_end;  
  char* _IO_buf_base;   
  char* _IO_buf_end;    
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;

  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; 

#define __HAVE_COLUMN 
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
 */
