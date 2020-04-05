#include <string.h>
#include <stdlib.h>
#include "headers.h"
#include <unistd.h>
#include <sys/ptrace.h>


__attribute__((no_sanitize("undefined")))int virusFunc(int test) {
  test += 1;  
  return (test * 100);
}


static int getLengthOfInt(int toCheck) {
  int size = 0;
  while (toCheck > 0) {
    size++;
    toCheck /= 10;
  }
  return (size);
}

int main(int argc, char **argv) {
  char *pid;
  char *AddrLibcTracee = NULL;
  char *AddrLibcTracer = NULL;

  //We start by checking our args, verifying that we have the right number of them
  if (argc != 3){
    printf("Usage: sudo ./tracer tracee f1\n");
    printf("tracee being the name of the executable we would like to inject our code in.\n");
    printf("And f1 being the name of the function being continously called inside our tracee.\n");
    return -1;
  }
  //We also verify if one of them is a -h, in that case we also display our usage
  for (int i = 0; i < argc;i++) {
    if (strcmp(argv[i], "-h") == 0) {
      printf("Usage: sudo ./tracer tracee f1\n");
      printf("tracee being the name of the executable we would like to inject our code in.\n");
      printf("And f1 being the name of the function being continously called inside our tracee.\n");
      return 0;
    }
  }

  //We start by getting the necessary informations that our tracer will need for subsequent step
  //The pid of the tracer and its length
  const int pidTracer = getpid();
  const int lengthPidTracer = getLengthOfInt(pidTracer);

  //The address of the f1 function inside our tracee, the pid of the tracee is also retrieved here

  DEBUG_PRINT("1");
  const long funcAddrF1 = step1(argv[1],argv[2], &pid);  
  const int pidTracee = atoi(pid);
  //We also get its length
  const size_t lengthOfPid = strlen(pid);

  free(pid);
  //We get the address of the beginnning of the libc for both our tracee and tracer
  AddrLibcTracee = getAddrLibcOf(pidTracee, lengthOfPid, AddrLibcTracee);
  AddrLibcTracer = getAddrLibcOf(pidTracer, (size_t)lengthPidTracer, AddrLibcTracer);

  //Before going on to step 2 to step 7, we attach our tracer to our tracee
  attachAndWait(pidTracee);

  //We execute our step2
  DEBUG_PRINT("2");
  step2(funcAddrF1, pidTracee, lengthOfPid);
  
  //We get the address of our function f2, used for our step3.
  //Since we are reusing our function getAddrFuncOfExec, our pid will be reset,
  //Since we do not need it we immediatly free it
  const long funcAddrF2 = step1(argv[1],"f2", &pid);
  free(pid);
  
  //The following are the function called for each step.
  //You may execute them one by one, or all at once with some exception
  //step5, 6 and the two type of step 7 need pagesize, so step4 must be done too.
  //For step7, you should not execute the trampoline and the indirect call together
  //This would cause the program to crash, which is normal considering that our trampoline
  //overwrite without anycleanup afterward
  DEBUG_PRINT("3");
  step3(funcAddrF1, funcAddrF2, pidTracee, lengthOfPid);

  DEBUG_PRINT("4");
  const int pagesize = step4(funcAddrF1, pidTracee, lengthOfPid, AddrLibcTracee, AddrLibcTracer);

  DEBUG_PRINT("5");
  step5(funcAddrF1, pidTracee, lengthOfPid, pagesize, AddrLibcTracee, AddrLibcTracer);

  DEBUG_PRINT("6");
  step6(funcAddrF1, pidTracee, lengthOfPid, pagesize, pidTracer, lengthPidTracer, AddrLibcTracee, AddrLibcTracer);

  //DEBUG_PRINT("7-Trampoline");
  //step7Trampoline(funcAddrF1, pidTracee, lengthOfPid, pagesize, pidTracer, lengthPidTracer, AddrLibcTracee, AddrLibcTracer);
  DEBUG_PRINT("7-Indirect Call");
  step7(funcAddrF1, pidTracee, lengthOfPid, pagesize, pidTracer, lengthPidTracer, AddrLibcTracee, AddrLibcTracer);

  //After we are done with our execution, we detach our tracer from our tracee
  if (ptrace(PTRACE_DETACH, pidTracee, NULL, NULL) < 0) {
    perror("Main: PTRACE_DETACH");
    exit(EXIT_FAILURE);
  }

  //Finish cleaning up our allocated memory, and exit our program
  free(AddrLibcTracee);
  free(AddrLibcTracer);
  return (EXIT_SUCCESS);
}
