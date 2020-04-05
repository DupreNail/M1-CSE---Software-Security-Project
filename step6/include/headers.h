
#ifndef HEADERS
# define HEADERS
#include <stdio.h>
long step1(char **argv, char **pid);
void step2(long funcAddr, char *pid);
void step3(char **argv, long funcAddr, long funcAddrf2, char *pid);
int step4(char **argv, char *pid, long funcAddr);
long step5(char **argv, char *pid, long funcAddr, int pagesize, char **AddrLibcTracee, char **AddrLibcTracer);
void step6(char **argv, char *pid, long funcAddr, int pagesize);
int virus(int test);
void displayAtAddr(FILE *fp, long funcAddr, int read_size);
#endif /* !HEADERS */


#define MALLOC_SIZE 128
