#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "headers.h"

/**
This function give us the address of the libc of the program of pid pid.
@param pid , of the executable we wish to find the libc address of. 
       pidLength, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
       addrLibc, a pointer to char representing the Addrof the libc of the executable  
@return a pointer to char representing the address of the libc of our executable
 **/
char *getAddrLibcOf(const int pid, const size_t pidLength, char *addrLibc) {

  char * command;
  char *buffer;
  FILE *fp;

  buffer = malloc(sizeof(char) * MALLOC_SIZE);                                         
  command = malloc(sizeof(char) * (strlen("cat /proc//maps") + pidLength + 1));       //fp will contains the result of cat /proc/pid/maps, in this project, the pid are those of the tracee and the tracer
  sprintf(command, "cat /proc/%d/maps",pid);                                        
  fp = popen(command, "r");
  if (fp == NULL) {
    perror("getAddrLibcOf: FOPEN");
    exit(EXIT_FAILURE);
  }
  while (fgets(buffer, MALLOC_SIZE, fp) != NULL) {                                   //We then go through all the content of fp until  
    if ((strstr(buffer, "libc") != NULL) && (strstr(buffer, "r-xp") != NULL)) {      //We find a line containing both libc and the r-xp, which means read that it have both the read and execute rights
      strtok(buffer, "-");                                                           //We then select only the first part of the address range, meaning that we now have the beginning of the libc
      break;                                                                         //in our buffer
    }
  }
  addrLibc = strdup(buffer);                                                         //we duplicate our buffer and store it inside addLibc
  fclose(fp);
  free(command);
  free(buffer);
  DEBUG_STRING("Address of Libc returned", addrLibc);
  return (addrLibc);                                                                 //which we return
}



/**
   Call a function that can be found in the libc of the tracee. 
@param funcAddr , the address of the function to call
       regsToSet, the regs to set in order to call our function accordingly
       pidtracee, the pid of our tracee
       lengthOfPid, the length of the pid
       possible arguments for the function to call
@return a pointer to the return of the called function, or null
 **/
struct user_regs_struct callFunction(const long funcAddr, const struct user_regs_struct regsToSet, const int pidTracee, const size_t lengthOfPid) {

  struct user_regs_struct regs;
  struct user_regs_struct backupRegs;

  unsigned char *backupMem;
  unsigned char *breakpointTrap;
  unsigned char *indirectCall;
  char *toOpen;

  indirectCall = malloc(sizeof(unsigned char) * 3);                              //callFunction starts by allocating the memory to store both our indirect call and our backupMemory
  backupMem = malloc(sizeof(unsigned char) * 3);
  breakpointTrap = malloc(sizeof(unsigned char) * 1);
  breakpointTrap[0] = 0XCC;
  indirectCall[0] = 0XFF; 
  indirectCall[1] = 0XD0;
  indirectCall[2] = 0XCC;                                                        //We "fill" our indirect call with the corresponding opcode, an indirect call and then a software interrupt

  toOpen = malloc(sizeof(char) * strlen("/proc//mem") + lengthOfPid + 1);
  sprintf(toOpen, "/proc/%d/mem",pidTracee);         

  backupAndWriteAt(toOpen, funcAddr, backupMem, breakpointTrap, 1, 3);           //We start by writing our software breakpoint at the beginning of our function f1

  ptrace(PTRACE_GETREGS, pidTracee, NULL, &regs);                                //We then get the current register twice, one that we will keep for our "cleanup" and one that will be used to set our
  ptrace(PTRACE_GETREGS, pidTracee, NULL, &backupRegs);                          //values accordingly. 
  regs.rip = regsToSet.rip;                                                      //We change our instruction pointer to the beginning of f1
  regs.rax = regsToSet.rax;                                                      //and our rax to the address of the function we wish to call.
                                                                                 
  if (regsToSet.rdi != 0) {                                                      //If the reg structure has its fields rdi, rsi and rdx not set to zero then we change our register to these value
    if (regsToSet.rdi == POSIX_MEM) {                                            //Special case for posix_mem, since it is dependant on the value in regs.rsp, that we can not know in advance
      regs.rdi = regs.rsp - 64; 
    }
    else {
      regs.rdi = regsToSet.rdi;
    }
  }
  
  if (regsToSet.rsi != 0) {
    regs.rsi = regsToSet.rsi;
  }
  if (regsToSet.rdx != 0) {
    regs.rdx = regsToSet.rdx;
  }                                                                               //The register may have been modified, but the change are not set as long as ptrace(PTRACE_SETREGS...) is not called
  

  contAndWait(pidTracee);                                                         //We send a signal cont to our tracee so that it may "hit" our software interrup previously written

  unsigned char *dummy = malloc(sizeof(unsigned char) * 3);                 
  backupAndWriteAt(toOpen, funcAddr, dummy, indirectCall, 3, 3);                  //We then write our indirect call/ software interrup in the memory, we do not need to backup what is at the
                                                                                  //beginning of f1, since it 
  free(dummy);                                                                    //will be the opcode of software interrupt and two other unrelated opcode.We are thus freing our dummy without using it 
  ptrace(PTRACE_SETREGS, pidTracee, NULL, &regs);                                 //We THEN set our rhe previously modified regs 
  contAndWait(pidTracee);                                                         //We ask the tracee to continue its execution, it will hit our indirect call, and check its register for the values,
                                                                                  //which we have just set.
  ptrace(PTRACE_GETREGS, pidTracee, NULL, &regs);                                 //It then hit the software interrupt allowing us to get the currents register to check the return value of the
                                                                                  //function that we have called for example  
  ptrace(PTRACE_SETREGS, pidTracee, NULL, &backupRegs);                           //We set the register to what it was before the first time we wrote inside the memory.


  rewriteBackupAt(toOpen, funcAddr, backupMem, 3);                                //We rewrite our backup, and let the program run as if nothing happened

  free(toOpen);
  free(backupMem);
  free(breakpointTrap);
  free(indirectCall);
  return (regs);                                                                  //the register containing the result of our call are returned
}

/**
   Function representing the fourth step of our project
   @param  funcAddrF1 , the address that we will read/write from/at
           pid, the pid of our tracee
           sizeOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
           AddrLibcTracee, a pointer to char representing the address of the libc of our tracee
	   AddrLibcTracer, a pointer to char representing the address of the libc of our tracer
   @return the pagesize of our tracee
 **/

int step4(const long funcAddrF1, const int pid, const size_t lengthOfPid, char *AddrLibcTracee, char *AddrLibcTracer) {
  
  long AddrPage = strtol(AddrLibcTracee, NULL, 16);   //We start by computing the address of getpagesize(). We have at our disposal the address of both libc (tracee and tracer) and the "position" of    
  AddrPage -= +strtol(AddrLibcTracer, NULL, 16);      //getpagesize in the libc of the tracer. To get the address of getpagesize in the libc of the tracee, we merely have to do 
  AddrPage += (long)getpagesize;                      //substract the address of the libc of our tracer from the one of our tracee, and then add the "position" of getpagesize.
                                                      
  struct user_regs_struct regs;                       //Same raisonning as step3, this time rax contain the address just computing, "pointing" to the address of getpagesize in the libc of the tracee
  regs.rip = (unsigned long long)funcAddrF1;       
  regs.rax = (unsigned long long)AddrPage;                 
  regs.rdi = 0;                                       //getpagesize does not take any parameters, we set our tree registers to zero
  regs.rsi = 0;
  regs.rdx = 0;

  regs = callFunction(funcAddrF1, regs, pid, lengthOfPid); //We then call callFunction, which will return the result of our call, here the pagesize of our tracee is stored in regs.rax

  DEBUG_INT("Pagesize", (int)regs.rax);
  return ((int)regs.rax);                                       //which we return
}
