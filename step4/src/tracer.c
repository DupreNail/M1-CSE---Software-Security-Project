#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"

int main(int argc, char **argv) {
  long  funcAddr;
  long funcAddrf2;
  char *pid;
  if (argc != 3){
    return -1;
  }

  funcAddr = step1(argv, &pid);
  printf("Pid of %s is %s\n", argv[1], pid);
  printf("Address of function %s is :%lx\n", argv[2], funcAddr);
  // step2(funcAddr, pid);
  argv[2] = strdup("f2");
  funcAddrf2 = step1(argv, &pid);
  step3(argv, funcAddr, funcAddrf2, pid);
  step4(argv, pid, funcAddr);
  free(pid);
  return (EXIT_SUCCESS);
}
