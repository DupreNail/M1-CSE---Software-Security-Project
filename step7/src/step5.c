#include <stdlib.h>
#include "headers.h"

/**
   Function representing the fifth step of our project
   @param  funcAddrF1 , the address that we will read/write from/at in our tracee
           pid, the pid of our tracee
           lengthOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   pagesize, the pagesize of our tracee, returned by step4
	   AddrLibcTracee, a pointer to char representing the address of the libc of our tracee
	   AddrLibcTracer, a pointer to char representing the address of the libc of our tracer
   @return the address of the memory returned by mprotect
 **/
long step5(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, char *AddrLibcTracee, char *AddrLibcTracer){

  long AddrPosix = strtol(AddrLibcTracee, NULL, 16);    //We compute the address of posix_memalign exactly as we did for getpagesize in the function step4
  AddrPosix -= +strtol(AddrLibcTracer, NULL, 16);
  AddrPosix += (long)posix_memalign;

  struct user_regs_struct regs;
  regs.rip = (unsigned long long)funcAddrF1;
  regs.rax = (unsigned long long)AddrPosix;                                 //Same as step4, rax contain the address of posix_mem in the lbic of the tracee
  regs.rdi = POSIX_MEM;                                 //We set rdi to the macro POSIX_MEM, in order to indicate to callFunction that this is a special case, since we will have to use rsp,
                                                        //another register, in order to properly call posix_memalign. rdi will be set to the value containing in rsp which we will have substracted an
                                                        //arbitrary (but still in accordance with the man) value. 
  regs.rsi = 32;                                        //rsi will be the alignement, must be a power of two and a multiple of (void*), 8 in our case
  regs.rdx = (unsigned long long)pagesize;                                  //the size of the allocation, we here choose to allocate a whole page.

  regs = callFunction(funcAddrF1, regs, pid, lengthOfPid);

  DEBUG_LONG("Mprotect memory ", (long)regs.rdi);     //regs.rdi is supposed to contain a value within the heap, while regs.rax contain 0 is the call was a success. 
  DEBUG_INT("Mprotect return value ", (int)regs.rax);
  return ((long)regs.rdi);
}
