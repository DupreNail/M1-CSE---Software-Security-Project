
#ifndef HEADERS
# define HEADERS
long step1(char **argv, char **pid);
void step2(long funcAddr, char *pid);
void step3(char **argv, long funcAddr, long funcAddrf2, char *pid);
void step4(char **argv, char *pid, long funcAddr);
#endif /* !HEADERS */


#define MALLOC_SIZE 128
