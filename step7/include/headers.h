
#ifndef HEADERS
# define HEADERS
#include <stdio.h>
#include <sys/user.h>

//ptrace_utils.c
void attachAndWait(const int pidToAttach);
void contAndWait(const int pid);

//step1.c
long step1(char *execName, char *functionName, char **pid);

//step2.c
void displayAtAddr(char *toOpen, const long funcAddr, const size_t read_size);
void backupAndWriteAt(char *toOpen, const long funcAddr, unsigned char *backup, unsigned char *toWrite, const size_t sizeOfWrite, const size_t sizeOfRead);
void rewriteBackupAt(char *toOpen, const long funcAddr, unsigned char* backup, const size_t lengthOfBackup);
void step2(const long funcAddr, const int pidTracee, const size_t lengthOfPid);

//step3.c
void step3(const long funcAddr, const long funcAddrf2, const int pidTracee, const size_t lengthOfPid);

//step4.c
char * getAddrLibcOf(const int pid, const size_t pidLength, char *addrLibc) ;
struct user_regs_struct callFunction(const long funcAddr, const struct user_regs_struct regsToSet, const int pidTracee, const size_t lengthOfPid);
int step4(const long funcAddrF1, const int pid, const size_t lengthOfPid, char *AddrLibcTracee, char *AddrLibcTracer);

//step5.c
long step5(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, char *AddrLibcTracee, char *AddrLibcTracer);

//step6.c
unsigned int getVirusLength(void);
long step6(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer);

//step7.c
void getVirus(const unsigned int lengthVirus, unsigned char * virus, const int pidTracer, const int lengthPidTracer);
void writeVirus(const int pid, const size_t lengthOfPid, const long memAlignRes, unsigned char *virus, const unsigned int lengthVirus);
void step7Trampoline(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer);
void step7(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer);

//tracer.c
int virusFunc(int test);


#endif /* !HEADERS */

#ifdef DEBUG_MODE
#define DEBUG_INT(x, y){fprintf(stderr,"In file: %s, in function:%s and at line: %d %s is %d\n",__FILE__,__func__,__LINE__, x, y);}
#define	DEBUG_STRING(x, y){fprintf(stderr,"In file: %s, in function:%s and at line: %d %s is %s\n",__FILE__,__func__,__LINE__, x, y);}
#define DEBUG_LONG(x, y){fprintf(stderr,"In file: %s, in function:%s and at line: %d %s is %lx\n",__FILE__,__func__,__LINE__, x, y);}
#define DEBUG_PRINT(x){fprintf(stderr,"\nBeginning of step: %s\n", x);}

#else
#define DEBUG_INT(x, y)
#define DEBUG_STRING(x, y)
#define DEBUG_LONG(x,y)
#define DEBUG_PRINT(x)
#endif

#define MALLOC_SIZE 128
#define POSIX_MEM -1llu
