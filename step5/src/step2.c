#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include "headers.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

//Test/debug function, used to display the memory at funcAddr in fp, using read_size
void displayAtAddr(FILE *fp, long funcAddr, int read_size){
  char *read_buffer = malloc(sizeof(unsigned char) * read_size);
  fseek(fp, funcAddr, SEEK_SET);
  fread(read_buffer, sizeof(read_buffer), 1, fp);
  for (int b = 0; b < (int)(sizeof(unsigned char) * read_size); b++)
    {
      if (b > 0) printf(":");
      printf("%02X", read_buffer[b]);
    }
  free(read_buffer);
}


unsigned char backupAndWrite(FILE *fp, long funcAddr, unsigned char backup, unsigned char breakpointTrap){
  fseek(fp, funcAddr, SEEK_SET);
  fread(&backup, 1, 1, fp);  
  fseek(fp, funcAddr, SEEK_SET);
  if ((fwrite(&breakpointTrap, 1,1, fp)) != 1) {
    perror("FWRITE");
  }
  return (backup);
}

void step2(long funcAddr, char *pid){
  int pidTracee;
  char *toOpen;
  FILE *fp;
  unsigned char breakpointTrap = 0XCC;
  unsigned char backup;
  
  pidTracee = atoi(pid);
  if (ptrace(PTRACE_ATTACH, pidTracee, 0,0) < 0){
    perror("ATTACH ERROR");
    exit(1);
  }
  if (waitpid(pidTracee, NULL, 0) != pidTracee){
    perror("FIRST WAITPID");
  }
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + strlen(pid)));
  sprintf(toOpen, "/proc/%d/mem",pidTracee);
  
  if ((fp = fopen(toOpen, "r+")) == NULL){
    perror("exit failure on fp");
    exit(EXIT_FAILURE);
  }
  backupAndWrite(fp, funcAddr, backup, breakpointTrap);
  
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
  sleep(2);
  if ((fp = fopen(toOpen, "r+")) == NULL) {
    perror("FOPEN");
  }
  free(toOpen);
  fseek(fp, funcAddr, SEEK_SET);
  if (fwrite(&backup, 1,1,fp) != 1) {
    perror("FWRITE");
  }  
  if (fclose(fp) < 0) {
    perror("FCLOSE");
  }
  if (ptrace(PTRACE_DETACH, pidTracee, NULL, NULL) < 0) {
    perror("PTRACE_DETACH");
  }
}
