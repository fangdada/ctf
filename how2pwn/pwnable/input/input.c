#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
int main()
{
  int pipe_stdin[2] = {-1,-1}, pipe_stderr[2] = {-1, -1};
  char *argv[101] = {0};
  /* stage 3 */
  char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};
  FILE *fp = NULL;
  pid_t pid_child;
  
  /* stage 1 */
  argv[0] = "/home/input2/input";
  for(int i=1;i<100;i++)
  {
    argv[i] = "a";
  }
  argv['A'] = "\x00";
  argv['B'] = "\x20\x0a\x0d";
  argv['C'] = "55555";
  argv[100] = NULL;
  
  /* stage 4 */
  fp = fopen("\x0a","wb");
  if(!fp)
  {
    perror("Cannot open file.");
    exit(-1);
  }
  fwrite("\x00\x00\x00\x00",4,1,fp);
  fclose(fp);
  fp = NULL;
  
  /* stage 2 */
  if(pipe(pipe_stdin) < 0 || pipe(pipe_stderr) < 0)
  {
    perror("Cannot create pipe!");
    exit(-1);
  }
  
  if((pid_child = fork()) < 0)
  {
    perror("Cannot create child process!");
    exit(-1);
  }
  
  if(pid_child == 0)
  {
    //子进程先等待父进程重定向pipe read，然后关闭不使用的pipe read
    //继而向两个pipe write对应的字符串，父进程此时已经把pipe read重定向到stdin和stderr
    //最终由input程序接收
    sleep(1);
    close(pipe_stdin[0]);	
    close(pipe_stderr[0]);
    write(pipe_stdin[1], "\x00\x0a\x00\xff", 4);
    write(pipe_stderr[1], "\x00\x0a\x02\xff", 4);
  }
  else
  {
    //父进程无需pipe write操作，首先close掉，然后把两个pipe read重定向到0和2
    //也就是stdin和stderr
    close(pipe_stdin[1]);
    close(pipe_stderr[1]);
    dup2(pipe_stdin[0], 0);
    dup2(pipe_stderr[0], 2);
    execve("/home/input2/input", argv, envp);
  }
  
  /* stage 5 */
  sleep(5);
  int sockfd;
  struct sockaddr_in saddr;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1)
  {
    perror("Cannot create socket!");
    exit(-1);
  }
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  saddr.sin_port = htons(55555);
  if(connect(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0)
  {
    perror("Cannot connect to server!");
    exit(-1);
  }
  write(sockfd, "\xde\xad\xbe\xef", 4);
  close(sockfd);
  
  return 0;
}

/*  
ln -s /home/input2/flag flag 
*/

