#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>


#include "headers.h"
void step4(char **argv, char *pid, long funcAddr) {

  char *AddrLibcTracee;
  char *AddrLibcTracer;
  FILE *fp;
  char *tempBuff;
  char *buffer = malloc(sizeof(char) * MALLOC_SIZE);
  const int pidTracee = atoi(pid);
  const int pidTracer = getpid();
  int pidlength = 0;
  int temp = pidTracer;
  char * command = malloc(sizeof(char) * (strlen("cat /proc//maps") + strlen(pid) + 1));
  sprintf(command, "cat /proc/%s/maps",pid);
  
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }
  while (fgets(buffer, MALLOC_SIZE, fp) != NULL) {
    if ((strstr(buffer, "libc") != NULL) && (strstr(buffer, "r-xp") != NULL)) {      
      tempBuff = strtok(buffer, "-");
        break;
    }
  }  
  fclose(fp);
  AddrLibcTracee = strdup(tempBuff);


  while (temp != 0) {
    pidlength+=1;
    temp = temp / 10;
  }
  free(buffer);
  buffer = malloc(sizeof(char) * MALLOC_SIZE);
  command = malloc(sizeof(char) * (strlen("cat /proc//maps") + pidlength + 1));
  sprintf(command, "cat /proc/%d/maps",pidTracer);
  printf("command:%s\n", command);
  fflush(0);
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }
  while (fgets(buffer, MALLOC_SIZE, fp) != NULL) {
     if ((strstr(buffer, "libc") != NULL) && (strstr(buffer, "r-xp") != NULL)) {
       AddrLibcTracer = strtok(buffer, "-");
       printf("\nTracer: %s\n", AddrLibcTracer);
       break;
    }
  }
  
   fclose(fp);

  
  long AddrPage = strtol(AddrLibcTracee, NULL, 16);
  printf("page 1:%lx\n", AddrPage);

  AddrPage -= +strtol(AddrLibcTracer, NULL, 16);
  printf("page 2:%lx\n", AddrPage); 
   AddrPage += (long)getpagesize;




   
   struct user_regs_struct regs;
   struct user_regs_struct backup;
   
   char *memory = malloc(sizeof(char) * 3);
   unsigned char breakpointTrap = 0XCC;
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
   regs.rax = (long)AddrPage;
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
   printf("\nRETURN VALUE:%lld\n", regs.rax);
   fflush(0);
   
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
