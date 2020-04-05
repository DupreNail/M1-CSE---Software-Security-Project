#include "headers.h"


/**
   Function representing the third step of our project
   @param  funcAddr , the address that we will read/write from/at
           funacAddrF2, the address of the function that is supposed to be called in F1.
           pidTracee, the pid of our tracee
           sizeOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
 **/
void step3(const long funcAddr, const long funcAddrf2, const int pidTracee, const size_t lengthOfPid) {
  const int param = 10;
  struct user_regs_struct regs;                          //We set our register accordingly, so that our indirect call have the right value available, here the address of f2, and a parameter
  regs.rip = (unsigned long long)funcAddr;               //Our rip will be at the beginning of our "target function" in our target executable
  regs.rax = (unsigned long long)funcAddrf2;             //Our indirect call will use rax to know what function it is supposed to call. rax is supposed to contain the address of f2
  regs.rdi = param;                                      //rdi will stock our first parameter
  regs.rsi = 0;                                          //rsi and rdx are both set to zero, this is so that we may reuse the callFunction even when they need to be set...
  regs.rdx = 0;                                          //...for a call to mprotect for example.
  regs = callFunction(funcAddr, regs, pidTracee, lengthOfPid);
  printf("Step 3 - Return of f2 function: %lld\n", regs.rax);
}
