#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include "headers.h"
#include <sys/mman.h>


/**
   function that will "get" and return our virus
   return nothing, but the unsigned char * will be "filled"
   @param  lengthVirus ,the length of the virus
           virus, pointer to unsigned char that will contain the virus
	   pidTracer, the pid of four Tracer
	   lengthPidTracer, the length of pidTracer
 **/
void getVirus(const unsigned int lengthVirus, unsigned char * virus, const int pidTracer, const int lengthPidTracer){
  FILE *fp;
  char *toOpen;
  
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + (unsigned long)lengthPidTracer + 1));
  sprintf(toOpen, "/proc/%d/mem",pidTracer);
  if ((fp = fopen(toOpen, "r+")) == NULL){                                        //fp will contains the result of cat /proc/pid/maps, the pid is the one of the tracer
    perror("backupAndWriteAt: FOPEN");
    exit(EXIT_FAILURE);
  }
  if (fseek(fp, (long)virusFunc, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                               //We place our file position indicator to the beginning of our function virus
  if (fread(virus, lengthVirus, 1, fp) != 1){                                     //We "store" it inside our pointer to unsigned char virus
    perror("backupAndWriteAt: READ");
      exit(EXIT_FAILURE);
  }
  if (fclose(fp) != 0) {                                                          //We close our file descriptor and free what is necessary
    perror("backupAndWriteAt: FCLOSE");
    exit(EXIT_FAILURE);
  }
  free(toOpen);
}

/**
   function that will write our virus to the given address
   @param  pid ,the pid of our tracee
           lengthOfPid, the length of our pid
	   memAlignRes, the result of our call to memalign, and where we will write our virus
	   virus, what will be written
	   lengthVirus, the length of our virus
 **/
void writeVirus(const int pid, const size_t lengthOfPid, const long memAlignRes, unsigned char *virus, const unsigned int lengthVirus){
  char *toOpen;
  unsigned char *virusCheck;                                                    //This will be used to compare what was written to our actual virus, to check if it was correctly written in full
  FILE* fp;
  toOpen = malloc(sizeof(char) * (strlen("/proc//mem") + lengthOfPid + 1));
  virusCheck = malloc(sizeof(unsigned char)* lengthVirus + 1);

  sprintf(toOpen, "/proc/%d/mem",pid);
  if ((fp = fopen(toOpen, "r+")) == NULL){                                      //We open /proc/pid/mem where pid is the pid of our tracee
    perror("writeVirus: FOPEN");
    exit(EXIT_FAILURE);
  }
  if (fseek(fp, memAlignRes, SEEK_SET) != 0) {
    perror("writeVirus: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                             //We place our file position indicator at the address that was given by the call to memAlign


  if ((fwrite(virus, lengthVirus, 1, fp)) != 1) {                               //we write our virus in full at this emplacement
    perror("backupAndWriteAt: FWRITE");
    exit(EXIT_FAILURE);
  }

  if (fseek(fp, memAlignRes, SEEK_SET) != 0) {
    perror("writeVirus: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                             //We place our file position indicator  at the same address (result of memAlign)

if (fread(virusCheck, lengthVirus, 1, fp) != 1){                                //We read what is written there (if our write was succefull, then it is the virus)
    perror("backupAndWriteAt: READ");
      exit(EXIT_FAILURE);
  }
  
  for (unsigned int i = 0; i < lengthVirus - 1; i++) {                          //We go through and compare each of unsigned char and check if there is any difference
    if (virus[i] != virusCheck[i]) {                                            //If there is not, our virus was succefully written at the address
      printf("Not the same between what was supposed to be writen and whats in the memory %d\n", i);
      fflush(0);
    }
  }
  if (fclose(fp) != 0) {                                                       //We close our file descriptor
    perror("writeVirus: FCLOSE");
    exit(EXIT_FAILURE);
  }
  free(toOpen);                                                                //and free what we have allocated.
  free(virusCheck);
}

/**
   Function actually "doing the work" to realise the trampoline
   This function, as a whole, follow the same "model" as callFunction, except that we are here using a trampoline, and that there is no cleanup afterwards
   @param  funcAddrF1 ,the address that we will read/write from/at in our tracee           
           pid, the pid of our tracee
           lengthOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on)
 **/
//this function, as a whole, follow the same "model" as callFunction, except that we are here using a trampoline, and that there is no cleanup afterwards
static void insertTrampoline(const long funcAddrF1, const int pid, const size_t lengthOfPid, const long memAlignRes) {
  char *toOpen;
  unsigned char *tramp;
  unsigned char *oline;
  unsigned char *breakpointTrap;
  FILE *fp;
  struct user_regs_struct regs;

  toOpen = malloc(sizeof(char) * strlen("/proc//mem") + (unsigned long)lengthOfPid + 1);                     
  tramp = malloc(sizeof(unsigned char)*2);                                  //We allocate the first part of our trampoline, give it the right opcode
  tramp[0] = 0x48;
  tramp[1] = 0xB8;
  
  oline = malloc(sizeof(unsigned char)*3);                                  //We do the same for the second part
  oline[0] = 0xFF;
  oline[1] = 0xE0;
  oline[2] = 0xC3;
    
  breakpointTrap = malloc(sizeof(unsigned char) * 1);                       //And we once again do the same thing for our breakpointTrap
  breakpointTrap[0] = 0XCC;          
  
  sprintf(toOpen, "/proc/%d/mem",pid);
  if ((fp = fopen(toOpen, "r+")) == NULL){                                  //We open the /proc/pid/mem, where pid is the pid of the tracee
    perror("insertTrampoline: FOPEN");
    exit(EXIT_FAILURE);
  }
  if (fseek(fp, funcAddrF1, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                         //place our file position indicator to the beginning of f1
  if ((fwrite(breakpointTrap, 1,1, fp)) != 1) {                             //write our software interupt
    perror("insertTrampoline: FWRITE");
    exit(EXIT_FAILURE);
  }
  free(breakpointTrap);
  if (fclose(fp) != 0) {                                                    //close our fp, and send a cont signal to the tracee
    perror("insertTrampoline: FCLOSE");
    exit(EXIT_FAILURE);
  } 
  contAndWait(pid);
  
  if ((fp = fopen(toOpen, "r+")) == NULL){                                 //We then reopen the same file as before
    perror("insertTrampoline: FOPEN");
    exit(EXIT_FAILURE);
  }
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);                                //get our regs, modify them so that rip, as usual, contains the address of the beginning of the function f1
  regs.rip = (unsigned long long)funcAddrF1;                               //and rdi contains the parameter to our virus
  regs.rdi = 10;

  if (fseek(fp, funcAddrF1, SEEK_SET) != 0) {
    perror("backupAndWriteAt: FSEEK");
    exit(EXIT_FAILURE);
  }                                                                        //We place our file position indicator to the beginning of f1
  if ((fwrite(tramp, 2,1, fp)) != 1) {                                     //write there the beginning of our rampoline
    perror("insertTrampoline: FWRITE");
    exit(EXIT_FAILURE);
  }
  if ((fwrite(&memAlignRes, sizeof(memAlignRes),1, fp)) != 1) {           //write the address of where our virus was written
    perror("insertTrampoline: FWRITE");
    exit(EXIT_FAILURE);
  }
  if ((fwrite(oline, 3,1, fp)) != 1) {                                    //and then write the second part of our trampoline
    perror("insertTrampoline: FWRITE");
    exit(EXIT_FAILURE);
  }
  free(tramp);                                      
  free(oline);                                                           //We do not need our trampoline opcode, we free them
  
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);                              //We set the regs that we modifed before
  if (fclose(fp) != 0) {                                                 //and close our file descriptor, letting our tracee run once again.
    perror("insertTrampoline: FCLOSE");                                  //It will stumble onto the trampoline and exit f1 right as it is exiting the virus function.
    exit(EXIT_FAILURE);
  }
  free(toOpen);                                                          //we free whatever we have left
}

/**
   Function representing the seventh step of our project, trampoline version
   @param  funcAddrF1 ,the address that we will read/write from/at in our tracee
           pid, the pid of our tracee
           lengthOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   pagesize, the pagesize of our tracee, returned by step4
	   pidTracer, the pid of our tracer
	   lengthPidTracer, the "length" of our tracers pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   AddrLibcTracee, a pointer to char representing the address of the libc of our tracee
	   AddrLibcTracer, a pointer to char representing the address of the libc of our tracer
 **/
void step7Trampoline(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer) {
  const long memAlignRes = step6(funcAddrF1, pid, lengthOfPid, pagesize,
				 pidTracer, lengthPidTracer, AddrLibcTracee, AddrLibcTracer);//We call our step6 in order to "set" our memory accordingly, by this we mean, get an address from the     
                                                                                             //HEAP + execution rights for this address 
  insertTrampoline(funcAddrF1, pid, lengthOfPid, memAlignRes);                               //We then call our function insertTrampoline, that will realize the second "path" of our step7
                                                                                             //using a trampoline
}

/**
   Function representing the first part of the seventh step of our project
   @param  funcAddrF1 ,the address that we will read/write from/at in our tracee
           pid, the pid of our tracee
           lengthOfPid, the "length" of our pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   pagesize, the pagesize of our tracee, returned by step4
	   pidTracer, the pid of our tracer
	   lengthPidTracer, the "length" of our tracers pid (I.E 1000 is 4, 10000 is 5 and so on) 
	   AddrLibcTracee, a pointer to char representing the address of the libc of our tracee
	   AddrLibcTracer, a pointer to char representing the address of the libc of our tracer
 **/

void step7(const long funcAddrF1, const int pid, const size_t lengthOfPid, const int pagesize, const int pidTracer, const int lengthPidTracer, char *AddrLibcTracee, char *AddrLibcTracer) {
  const long memAlignRes = step6(funcAddrF1, pid, lengthOfPid, pagesize,
				 pidTracer, lengthPidTracer, AddrLibcTracee, AddrLibcTracer);    //We call our step6 in order to "set" our memory accordingly, by this we mean, get an address from the 
                                                                                                 //HEAP + execution rights for this address
  struct user_regs_struct regsVirus;                                                             //We setup our call to the virus function
  regsVirus.rip = (unsigned long long)funcAddrF1;                                                //As always, rip contais the address of F1
  regsVirus.rax = (unsigned long long)memAlignRes;                                               //We've written our virus at address memAlignRes, we are thus "giving" this address to rax
  regsVirus.rdi = 100;                                                                           //Our virus function needs a int as parameter, we here give 100 
  regsVirus.rsi= 0;                        
  regsVirus.rdx = 0;                                                                             //No need for anymore parameter, we set rsi and rdx to 0
  regsVirus = callFunction(funcAddrF1, regsVirus, pid, lengthOfPid);                             //We call our virus in the tracee
  printf("STEP 7 - Return of Virus Function: %lld\n", regsVirus.rax);                            //Get the return value of the virus, display it, if everytinhg went well, it is (param + 1) * 100
                                                                                                 //with a parameter of 100, the result is 10100


  long AddrMProtect = strtol(AddrLibcTracee, NULL, 16);                                          //We must now clean any trace of our call, this start by changing the rights of our memory window back to
  AddrMProtect -= +strtol(AddrLibcTracer, NULL, 16);                                             //read and write only
  AddrMProtect += (long)mprotect;                                                                //We once again compute the address of mProtect in the libc of our tracee

  
  struct user_regs_struct regsM2;                                                                //We setup the regs that will be used to call Mprotect 
  regsM2.rip = (unsigned long long)funcAddrF1;                                                   //Once again the address of f1 in rip,
  regsM2.rax = (unsigned long long)AddrMProtect;                                                 //and the address of the function to call in rax
  regsM2.rdi = (unsigned long long)(memAlignRes &~(pagesize -1));                                //Mprotect take the aligned address (same as step 6) in first parameter
  regsM2.rsi = (unsigned long long)pagesize;                                                     //The size (same as step6) that we want to change the rights for
  regsM2.rdx = PROT_WRITE | PROT_READ;                                                           //And this time the originals rights of our data windows, which were WRITE and READ
  regsM2 = callFunction(funcAddrF1, regsM2, pid, lengthOfPid);                                   //We call mprotect with the abovementioned parameters


   long AddrFree = strtol(AddrLibcTracee, NULL, 16);                                             //We must then free the address that we got through memAlign, since it was allocated during its call
  AddrFree -= +strtol(AddrLibcTracer, NULL, 16);
  AddrFree += (long)free;                                                                        //We compute the address of free in the libc of the tracee

  struct user_regs_struct regsFree;                                                              //We setup the regs that will be used to call free
  regsFree.rip = (unsigned long long)funcAddrF1;                                                 //Once again the address of f1 in rip,
  regsFree.rax = (unsigned long long)AddrFree;                                                   //and the address of the function to call in rax
  regsFree.rdi = (unsigned long long)(memAlignRes &~(pagesize -1));                              //We free our address
  regsFree.rsi = 0;               
  regsFree.rdx = 0;                                                                              //no need for any other parameters
  regsFree = callFunction(funcAddrF1, regsFree, pid, lengthOfPid);                               //We call free with the abovementioned parameters

  const unsigned int lengthVirus = getVirusLength();                                             //Last step in our cleanup, overwriting our virus in the memory of the tracee
  unsigned char *empty = malloc(sizeof(unsigned char)*lengthVirus);                              //We create an unsigned char array of the size of our virus, filled with \0
  for (unsigned int i = 0; i < lengthVirus; i++) {
    empty[i] = '\0';
  }

                                                                                                 //We are NOT writing the virus again, merely using the
                                                                                                 //function in order to overwrite/clean where the virus was.
  writeVirus(pid, lengthOfPid, memAlignRes, empty, lengthVirus);                                 //We then reuse our function writeVirus to write this array to where the virus is, overwriting it.
  free(empty);
}
