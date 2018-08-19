#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

long long size_link[40]={0,};
long long string_link[40]={0,};
long long int added_times=0;
long long edit_times[40]={0,};

void safe_input(long long a1,unsigned int a2)
{
  char buf; 
  unsigned int i; 

  for ( i = 0; i < a2; ++i )
  {
    buf = 0;
    if ( read(0, &buf, 1) < 0 )
      printf("read() error");
    *(unsigned char *)(a1 + i) = buf;
    if ( buf == 10 )
      break;
  }
  *(unsigned char *)(a2 - 1 + a1) = 0;
}

long long get_input()
{
  long long result; 
  int v2; 
  char s[10]={0,};

  safe_input(s,0x10);
  v2 = atoi(s);
  if ( v2 >= 0 )
    result = v2;
  else
    result = 0;
  return result;
}

void ready()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
}

void menu()
{
  puts("1. New string");
  puts("2. Show string");
  puts("3. Edit string");
  puts("4. Delete string");
  puts("5. Exit");
  printf("choice: ");
}

void new_string()
{
  unsigned int size; 
  unsigned long long i; 
  unsigned int nmemb; 
  void *strings; 

  if ( added_times > 0x20 )
    printf("too many string");
  printf("please input string length: ");
  size = get_input();
  nmemb = size;
  if ( !size || size > 0x100 )
    printf("invalid size");
  strings = calloc(size, 1);
  if ( !strings )
  {
    printf("memory error");
    exit(1);
  }
  printf("please input the string content: ", 1);
  safe_input(strings, nmemb);
  for ( i = 0; i <= 31 && string_link[i]; ++i )
    ;
  if ( i > 31 )
    printf("too many string");
  string_link[i] = strings;
  printf("your string: %s\n", strings);
  ++added_times;
  size_link[i] = nmemb;
}

void edit_string()
{
  unsigned int index; 
  unsigned int strings_size; 
  unsigned int the_byte; 
  long long* strings; 

  printf("please input the index: ");
  index = get_input();
  if ( index > 0x1F )
  {
    printf("not a validate index");
    exit(1);
  }
  strings = string_link[index];
  if ( !strings )
  {
    printf("not a validate index");
    exit(1);
  }
  strings_size = size_link[index];
  if ( edit_times[index] <= 4 )
  {
    printf("input the byte index: ");
    the_byte = get_input();
    if ( the_byte <= strings_size )
    {
      //++*(unsigned char *)(the_byte + strings);
      ++*((unsigned char*)strings+the_byte);
      ++edit_times[index];
    }
    else
    {
      puts("nope!");
    }
  }
  else
  {
    puts("nope!");
  }
}

void del_string()
{
  unsigned int index;
  void *ptr; 

  printf("please input the index: ");
  index = get_input();
  if ( index > 0x1F )
    printf("not a validate index");
  ptr=string_link[index];
  if ( !ptr )
    printf("not a validate index");
  free(ptr);
}

void print_string()
{
  puts("Nothing :)");
}

int main(int argc,char** argv,char** envp)
{
  int choose;
  int v3;
  ready();
  if((signed int)argc > 1 )
  {
    v3 = atoi(argv[1]);
    alarm(v3);
  }

  
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choose = get_input();
      if ( choose != 1 )
        break;
      new_string();
    }
    switch ( choose )
    {
      case 2:
        print_string();
        break;
      case 3:
        edit_string();
        break;
      case 4:
        del_string();
        break;
      default:
        if ( choose == 5 )
          exit(0);
        puts("wrong choice");
        break;
    }
  }
}
