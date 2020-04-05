#include <string.h>
#include <stdlib.h>
#include "headers.h"
#include <unistd.h>

/**
    Test|debug function, used to display the memory at funcAddr in fp, using read_size
    @param toOpen , the path to the file that we will open and read from
           funcAddr, representing the address of the beginning of the range of data we will display
           read_size, the size that we will read
 **/
void displayAtAddr(char *toOpen, const long funcAddr, const size_t read_size){
  FILE * fp;
  if ((fp = fopen(toOpen, "r+")) == NULL){                              //We try to open our file with path is /proc/pidTracee/mem
    perror("displayAddr: FOPEN");
    exit(EXIT_FAILURE);
  }
  
  char *read_buffer = malloc(sizeof(unsigned char) * read_size);
  if (fseek(fp, funcAddr, SEEK_SET) != 0) {
    perror("displayAddr: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                    //we move our file pointer to the address of our function
  if (fread(read_buffer, sizeof(read_buffer), 1, fp) != 1) {
    perror("displayAddr: FREAD");
    exit(EXIT_FAILURE);
  }                                                                    //we read from our buffer containing the content of proc/prodTracee/mem
  for (int b = 0; b < (int)(sizeof(unsigned char) * read_size); b++)
    {
      if (b > 0) printf(":");
      printf("%02X", read_buffer[b]);                                  //We display waht we just read
    }
  free(read_buffer);
  if (fclose(fp) != 0) {
    perror("displayAddr: FCLOSE");
    exit(EXIT_FAILURE);
  }
}


/**
   Save sizeOfWrite characters in file with name toOpen, at funcAddr, in backup, and overwrite 
   with the content of toWrite at the same place
   return nothing, but since backup is a pointer the change on it will be repercuted
   @param  toOpen , the path to the file that we will open and read/write from
           funcAddr, representing the address of the beginning of the range of data we will save/overwrite
           backup, will contain what was writen at funcAddr
           toWrite, contain what is to be writen at funcAddr
           sizeOfWrite, the size/length of toWrite
           sizeOfRead, the size/length of toLength
 **/
void backupAndWriteAt(char *toOpen, const long funcAddr, unsigned char *backup, unsigned char *toWrite, const size_t sizeOfWrite, const size_t sizeOfRead) {
  FILE * fp;
  if ((fp = fopen(toOpen, "r+")) == NULL){
    perror("backupAndWriteAt: FOPEN");
    exit(EXIT_FAILURE);
  }
  if (fseek(fp, funcAddr, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }//We place our file pointer at the addr we wish to write at (usually f1)
  if (fread(backup, sizeOfRead, 1, fp) != 1) {
    perror("backupAndWriteAt: FREAD");
    exit(EXIT_FAILURE);
  }
  
  //We read at this address, the size is given in argument
  if (fseek(fp, funcAddr, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }                     //we replace our file pointer to the same position as the first time
  if ((fwrite(toWrite, sizeOfWrite, 1, fp)) != 1) {  //We write the content of toWrite (this can be a breakpoint, an indirect call...) at 
    perror("backupAndWriteAt: FWRITE");
    exit(EXIT_FAILURE);
  }
  if (fclose(fp) != 0) {
    perror("backupAndWriteAt: FCLOSE");
    exit(EXIT_FAILURE);
  }
}

/**
   At funcAddr of file toOpen, will overwrite with backup
   @param  toOpen , the path to the file that we will open and write in
           funcAddr, representing the address of the beginning of the range of data we will overwrite
           backup, contain what is to be rewritten at funcAddr
           lengthOfBAckup, the length.size of the backup
 **/
void rewriteBackupAt(char *toOpen, const long funcAddr, unsigned char* backup, const size_t lengthOfBackup) {
  FILE *fp;
  if ((fp = fopen(toOpen, "r+")) == NULL) {
    perror("rewriteBackupAt: FOPEN");
    exit(EXIT_FAILURE);

  }
  if (fseek(fp, funcAddr, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }                                                 //We place our file pointer at the addr we wish to write at (usually f1)
  if (fwrite(backup, lengthOfBackup, 1, fp) != 1) { //We try to rewrite our backup at this address, if this fail, we exit with an error
    perror("rewriteBackupAt: FWRITE");
    exit(EXIT_FAILURE);

  }
  if (fclose(fp) != 0) {                              //We then try to close our file descriptor, once again exiting if this fail.
    perror("rewriteBackupAt: FCLOSE");
    exit(EXIT_FAILURE);

  }
}

/**
   Function representing the second step of our project
   @param  funcAddr , the address that we will read/write from/at
           pidTracee, the pid of our tracee
           sizeOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
 **/
void step2(const long funcAddr, const int pidTracee, const size_t sizeOfPid){
  char *toOpen;
  unsigned char *backup;
  unsigned char *breakpointTrap;

    
  breakpointTrap = malloc(sizeof(unsigned char) * 1);                      //This will point towards an unsigned char containing 0XCC,the opcode for a software interrupt
  backup = malloc(sizeof(unsigned char) * 1);                              //This will be used to save what is written at the Address funcAddr in /proc/pidTracee/mem
  breakpointTrap[0] = 0XCC;                                                //For this step, both of them only need to be allocated one "space" in our memory, we still choose to use a pointer in order 
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + sizeOfPid + 1));  //to reuse our function backupAndWrite and rewriteBackupAt.
  sprintf(toOpen, "/proc/%d/mem",pidTracee);
  backupAndWriteAt(toOpen, funcAddr, backup, breakpointTrap, 1, 1);         //We save what is at Address funcAddr of /proc/pidTracee/mem before overwriting it with our software interrup

  sleep(2);                                                                 //Here to show the effect of our tracer on our tracee. This will stop our tracee for sleep(x) seconds.
  rewriteBackupAt(toOpen, funcAddr, backup, 1);                             //We then overwrite our software interrupt with what we saved in backupAndWrite, reverting the memory to its earlier state.

  free(toOpen);
  free(breakpointTrap);
  free(backup);                                                             //We free whatever is necessary.
}
