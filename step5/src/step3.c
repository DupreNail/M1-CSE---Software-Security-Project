#include "headers.h"
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


void step3(char **argv, long funcAddr, long funcAddrf2, char *pid) {
  struct user_regs_struct regs;
  struct user_regs_struct backup;
  int pidTracee = atoi(pid);
  char *memory = malloc(sizeof(char) * 3);
  unsigned char breakpointTrap = 0XCC;
  
  char *command;
  FILE *fp;
  if (ptrace(PTRACE_ATTACH, pidTracee, 0,0) < 0){
    perror("ATTACH ERROR");
    exit(1);
  }
  command = malloc(sizeof(char) * 128);
  if (waitpid(pidTracee, NULL, 0) != pidTracee){
    perror("WAITPID");
  }
  
  sprintf(command, "/proc/%d/mem",pidTracee);
  if ((fp = fopen(command, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }
  
  fseek(fp, funcAddr, SEEK_SET);
  fread(&memory, 3, 1, fp);
  if ((fwrite(&breakpointTrap, 1,1, fp)) != 1) {
    perror("FWRITE");
  }
  ptrace(PTRACE_GETREGS, pidTracee, NULL, &regs);
  ptrace(PTRACE_GETREGS, pidTracee, NULL, &backup);
  regs.rip = funcAddr;
  regs.rax = funcAddrf2;
  regs.rdi = 10;

  fseek(fp, funcAddr, SEEK_SET);
  unsigned char test[] = {0xFF, 0xD0, 0xCC};
  
  if (fwrite(&test, 3, 1, fp) <= 0){
    perror("FWRITE");
  }
  ptrace(PTRACE_SETREGS, pidTracee, NULL, &regs);
  if (fclose(fp) != 0) {
    perror("FCLOSE");
  }
  
  if (ptrace(PTRACE_CONT, pidTracee, NULL,NULL) < 0) {
    perror("ERROR CONT");
  }
    int wstatus;
  if (waitpid(pidTracee, &wstatus,0) != pidTracee){
    perror("WAITPID");
  }

  ptrace(PTRACE_GETREGS, pidTracee, NULL, &regs);

 if ((fp = fopen(command, "r+")) == NULL){
   perror("exit failure on fp");
   exit(EXIT_FAILURE);
 }

 fseek(fp, funcAddr, SEEK_SET);
 if (fwrite(&memory, 3,1,fp) != 1) {
   perror("FWRITE");
 }
 ptrace(PTRACE_SETREGS, pidTracee, NULL, &backup);
 if (ptrace(PTRACE_DETACH, pidTracee, NULL, NULL) < 0) {
   perror("PTRACE_DETACH");
 } 
}
