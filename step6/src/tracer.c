#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"

int virus(int test) {
  printf("Hello World!\n");
  fflush(0);
}


int main(int argc, char **argv) {
  long  funcAddr;
  long funcAddrf2;
  char *pid;
  int pagesize;
  if (argc != 3){
    return -1;
  }

  printf("Address Function Virus:%p\n",virus);
  funcAddr = step1(argv, &pid);
  printf("Pid of %s is %s\n", argv[1], pid);
  printf("Address of function %s is :%lx\n", argv[2], funcAddr);
  // step2(funcAddr, pid);
  argv[2] = strdup("f2");
  funcAddrf2 = step1(argv, &pid);
  //  step3(argv, funcAddr, funcAddrf2, pid);
  pagesize = step4(argv, pid, funcAddr);
  //step5(argv, pid, funcAddr, pagesize);
  step6(argv, pid, funcAddr, pagesize);
  free(pid);
  return (EXIT_SUCCESS);
}
