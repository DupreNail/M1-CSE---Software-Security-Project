#include <string.h>
#include <stdlib.h>
#include "headers.h"
#include <sys/mman.h>

/**
   Function used to get the length of our "virus" in our tracer
   @return the size of our virus
 **/
unsigned int getVirusLength() {
  char *buffer = malloc(sizeof(char) * MALLOC_SIZE);
  FILE *fp;
  char *length = NULL;
  char * command = malloc(sizeof(char) * (strlen("nm -S -t d tracer") + 1));   // -S=print-size ||| -t d=print in decimal. Both together mean that we print the size of virus in decimal 
  sprintf(command, "nm -S -t d tracer");
  fp = popen(command, "r");                                                    //Our file descriptor will contain the result of the command nm -S -t d tracer
  if (fp == NULL) {
    perror("getVirusLength: FOPEN");
    exit(EXIT_FAILURE);
  }
  while (fgets(buffer, MALLOC_SIZE, fp) != NULL) {                            //We get each line until
    if (strstr(buffer, "virusFunc") != NULL) {                                //We find one with virusFunc (the name of our function virus) in it
      strtok(buffer, " ");                                                    //We then isolate our size
      length = strtok(NULL, " ");
      break;
    }
  }
  
  unsigned int toReturn = 0;
  if (length != NULL){
    toReturn = (unsigned int)strtoul(length, NULL, 10);
  }
  pclose(fp);
  free(command);
  free(buffer);
  DEBUG_INT("Virus length", toReturn );
  return (toReturn);                                                           //and return it with an int
}


/**
   Function representing the sixth step of our project
   @param  funcAddrF1 , the address that we will read/write from/at in our tracee
           pid, the pid of our tracee
           lengthOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   pagesize, the pagesize of our tracee, returned by step4
	   pidTracer, the pid of our tracer
	   lengthPidTracer, the "length" of our tracers pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   AddrLibcTracee, a pointer to char representing the address of the libc of our tracee
	   AddrLibcTracer, a pointer to char representing the address of the libc of our tracer
   @return the address of the memory returned by mprotect
 **/

long step6(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer){

  const unsigned int lengthVirus = getVirusLength();                                                               //We get the virus "length", or size. This will be used to know how much byte we need to write
                                                                                                          //in the memory of the tracee
  const long memAlignRes = step5(funcAddrF1, pid, lengthOfPid, pagesize, AddrLibcTracee, AddrLibcTracer); //We call step5, save the result, this will be used ot know where we will write the virus in the 
                                                                                                          //tracee
  long AddrMProtect = strtol(AddrLibcTracee, NULL, 16);
  AddrMProtect -= +strtol(AddrLibcTracer, NULL, 16);
  AddrMProtect += (long)mprotect;                                                                         //We get the address of Mprotect in the libc of the tracee in the same way we did before

  const long AlignedMemAlignRes = memAlignRes  & ~(pagesize - 1);                                         //We must align to the page the address we got from step5, please see comment bellow step6 for 

  DEBUG_LONG("Return of memAlign", memAlignRes);
  DEBUG_LONG("Aligned return of memAlign", AlignedMemAlignRes);//an explication of this line
  struct user_regs_struct regs;                                                                           //We setup the regs that will be used to call Mprotect
  regs.rip = (unsigned long long)funcAddrF1;                                                                                  //Once again the address of f1 in rip,
  regs.rax = (unsigned long long)AddrMProtect;                                                                                //and the address of the function to call in rax
  regs.rdi = (unsigned long long)AlignedMemAlignRes;                                                                          //Mprotect take the aligned address in first parameter
  regs.rsi = (unsigned long long)pagesize;                                                                                    //The size that we want to change the rights for
  regs.rdx = PROT_EXEC | PROT_WRITE | PROT_READ;                                                          //And finally the rights to apply. We apply EXEC WRITE and READ because only applying exec
                                                                                                          //would remove the read and write rights, and we need to be able to read and write to this range
                                                                                                          //of data
  regs = callFunction(funcAddrF1, regs, pid, lengthOfPid);                                                //We call the function.

  unsigned char *virus;
  virus = malloc(sizeof(unsigned char)* lengthVirus + 1);                                                 //We malloc of array of unsigned char to the size that we got at the beginning of step6
  getVirus(lengthVirus, virus, pidTracer, lengthPidTracer);                                               //We "store" our virus inside this array
  writeVirus(pid, lengthOfPid, memAlignRes, virus, lengthVirus);                                          //We then write our virus to the designated position
  free(virus);
  return (memAlignRes);                                                                                   //We return memAlignRes because it will be usefull for our step7.
}


//Explication memAlignRes &~ (pagesize - 1):
//We want to align the address that memAlign has given us to our pagesize. For this example, lets say the address is 51231234, our pagesize 4096
//4096 - 1 give us 4095, which is 1111 in binary. we then apply the bitwise NOT operator ~ on this, giving us 0000.
//We then apply the bitwise or between our address and 0000, which will "force" our Address to be aligned to our pagesize.
//In our example, our address thus change from 51231234 to 51230000.
